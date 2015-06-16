#include <sys/types.h>          /*  See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/in.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_LEN              8192
#define BADRESP_RC	-2
#define ERROR_RC	-1
#define OK_RC		0
#define TIMEOUT_RC	1
#define AUTH_VECTOR_LEN		16
#define _PATH_DEV_URANDOM	"/dev/urandom"		/* Linux only */
#define AUTH_PASS_LEN           3 * 16 /*  multiple of 16 */ 
#define MGMT_POLL_SECRET        "testing123"
#define CHAP_VALUE_LENGTH               16
#define MAX(a,b) (a >= b ? a : b)

#define CHAP_VALUE_LENGTH		16

typedef struct pw_auth_hdr
{
	u_char          code;
	u_char          id; 
	u_short         length;
	u_char          vector[AUTH_VECTOR_LEN];
	u_char          data[2];
} AUTH_HDR;

static void rc_random_vector (unsigned char *vector)
{
	int             randno;
	int             i;
	int		fd;

/* well, I added this to increase the security for user passwords.
   we use /dev/urandom here, as /dev/random might block and we don't
   need that much randomness. BTW, great idea, Ted!     -lf, 03/18/95	*/

	if ((fd = open(_PATH_DEV_URANDOM, O_RDONLY)) >= 0)
	{
		unsigned char *pos;
		int readcount;

		i = AUTH_VECTOR_LEN;
		pos = vector;
		while (i > 0)
		{
			readcount = read(fd, (char *)pos, i);
			pos += readcount;
			i -= readcount;
		}

		close(fd);
		return;
	} /* else fall through */

	for (i = 0; i < AUTH_VECTOR_LEN;)
	{
		randno = random();
		memcpy ((char *) vector, (char *) &randno, sizeof (int));
		vector += sizeof (int);
		i += sizeof (int);
	}

	return;
}
#if 0

static int rc_check_reply (AUTH_HDR *auth, int bufferlen, char *secret,
			   unsigned char *vector, unsigned char seq_nbr)
{
	int             secretlen;
	int             totallen;
	unsigned char   calc_digest[AUTH_VECTOR_LEN];
	unsigned char   reply_digest[AUTH_VECTOR_LEN];

	totallen = ntohs (auth->length);

	secretlen = strlen (secret);

	/* Do sanity checks on packet length */
	if ((totallen < 20) || (totallen > 4096))
	{
		error("rc_check_reply: received RADIUS server response with invalid length");
		return (BADRESP_RC);
	}

	/* Verify buffer space, should never trigger with current buffer size and check above */
	if ((totallen + secretlen) > bufferlen)
	{
		error("rc_check_reply: not enough buffer space to verify RADIUS server response");
		return (BADRESP_RC);
	}
	/* Verify that id (seq. number) matches what we sent */
	if (auth->id != seq_nbr)
	{
		error("rc_check_reply: received non-matching id in RADIUS server response");
		return (BADRESP_RC);
	}

	/* Verify the reply digest */
	memcpy ((char *) reply_digest, (char *) auth->vector, AUTH_VECTOR_LEN);
	memcpy ((char *) auth->vector, (char *) vector, AUTH_VECTOR_LEN);
	memcpy ((char *) auth + totallen, secret, secretlen);
	rc_md5_calc (calc_digest, (char *) auth, totallen + secretlen);

#ifdef DIGEST_DEBUG
	{
		int i;

		fputs("reply_digest: ", stderr);
		for (i = 0; i < AUTH_VECTOR_LEN; i++)
		{
			fprintf(stderr,"%.2x ", (int) reply_digest[i]);
		}
		fputs("\ncalc_digest:  ", stderr);
		for (i = 0; i < AUTH_VECTOR_LEN; i++)
		{
			fprintf(stderr,"%.2x ", (int) calc_digest[i]);
		}
		fputs("\n", stderr);
	}
#endif

	if (memcmp ((char *) reply_digest, (char *) calc_digest,
		    AUTH_VECTOR_LEN) != 0)
	{
#ifdef RADIUS_116
		/* the original Livingston radiusd v1.16 seems to have
		   a bug in digest calculation with accounting requests,
		   authentication request are ok. i looked at the code
		   but couldn't find any bugs. any help to get this
		   kludge out are welcome. preferably i want to
		   reproduce the calculation bug here to be compatible
		   to stock Livingston radiusd v1.16.	-lf, 03/14/96
		 */
		if (auth->code == PW_ACCOUNTING_RESPONSE)
			return (OK_RC);
#endif
		error("rc_check_reply: received invalid reply digest from RADIUS server");
		return (BADRESP_RC);
	}

	return (OK_RC);

}
#endif

static int radius_pap_auth(char *username, char *password)
{
	AUTH_HDR *auth, *recv_auth;
	struct sockaddr salocal; struct sockaddr saremote;
	struct sockaddr_in *sin;
	struct timeval  authtime;
	fd_set          readfds;
	char            send_buffer[BUFFER_LEN];
	char            recv_buffer[BUFFER_LEN];
	unsigned char *buf;
	unsigned char vector[AUTH_VECTOR_LEN];
	unsigned char md5buf[256];
	int sockfd;
	unsigned int length;
	unsigned char secret[49];
	unsigned int total_length = 0;
	unsigned int salen;
	unsigned char   passbuf[MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char *pw_buf, *pw_vector;

	/*char *username = "user1";*/
	/*char *password = "123456";*/
	int padded_length;
	int secretlen;
	int pc, i;

	auth = malloc(sizeof(AUTH_HDR));
	if (auth == (AUTH_HDR *)NULL){
		printf("alloc auth failed\n");
		return -1;
	}

	auth = (AUTH_HDR *)send_buffer;
	buf = auth->data; 
	auth->code = 1;
	auth->id = 1;
	

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("sockfd failed\n");
		return; 
	}

	length = sizeof (salocal);
	sin = (struct sockaddr_in *) & salocal;
	memset ((char *) sin, '\0', (size_t) length);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons ((unsigned short) 0);
	if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||
		   getsockname (sockfd, (struct sockaddr *) sin, &length) < 0)
	{
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		/*error("rc_send_server: bind: %s: %m", server_name);*/
		/*return (ERROR_RC);*/
		printf("bind error\n");
		return -1;
	}

	rc_random_vector(vector);
	memcpy(auth->vector, vector, AUTH_VECTOR_LEN);

	*buf++ = 1; /*username*/ 
	*buf++ = 2 + strlen(username);
	memcpy(buf, username, strlen(username));
	total_length += 2 + strlen(username);

	buf += strlen(username) ;

/* Encrypt the password */

/* Chop off password at AUTH_PASS_LEN */
	*buf++ = 2;
	length = strlen(password);
	strcpy(secret, MGMT_POLL_SECRET);
	if (length > AUTH_PASS_LEN) length = AUTH_PASS_LEN;
	
	/* Calculate the padded length */
	padded_length = (length+(AUTH_VECTOR_LEN-1)) & ~(AUTH_VECTOR_LEN-1);
	
	/* Record the attribute length */
	*buf++ = padded_length + 2;
	
	/* Pad the password with zeros */
	memset ((char *) passbuf, '\0', AUTH_PASS_LEN);
	memcpy ((char *) passbuf, password, (size_t) length);
	
	secretlen = strlen (secret);
	pw_vector = auth->vector;

	for(i = 0; i < padded_length; i += AUTH_VECTOR_LEN) {
	    /* Calculate the MD5 digest*/
	    strcpy ((char *) md5buf, secret);
	    memcpy ((char *) md5buf + secretlen, pw_vector,
	            AUTH_VECTOR_LEN);
	    rc_md5_calc (buf, md5buf, secretlen + AUTH_VECTOR_LEN);
	
	    /* Remeber the start of the digest */
	    pw_vector = buf;
	
	    /* Xor the password into the MD5 digest */
	    for (pc = i; pc < (i + AUTH_VECTOR_LEN); pc++) {
	        *buf++ ^= passbuf[pc];
	    }
        }

	total_length += padded_length + 2 + 20;
	auth->length = htons ((unsigned short) total_length);

	sin = (struct sockaddr_in *) & saremote;
	memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	/*sin->sin_addr.s_addr = inet_addr("192.168.0.99");*/
	sin->sin_addr.s_addr = inet_addr("115.29.203.202");
	sin->sin_port = htons(1812);

	for (;;)
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			(struct sockaddr *) sin, sizeof (struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) 1;
		FD_ZERO (&readfds);
		FD_SET (sockfd, &readfds);
		if (select (sockfd + 1, &readfds, NULL, NULL, &authtime) < 0) {
			/*if (errno == EINTR)*/
				/*continue;*/
			/*error("rc_send_server: select: %m");*/
			memset (secret, '\0', sizeof (secret));
			close (sockfd);
			return -1;
		}
		if (FD_ISSET (sockfd, &readfds))
			break;
	}
	salen = sizeof (saremote);
	length = recvfrom (sockfd, (char *) recv_buffer,
			   (int) sizeof (recv_buffer),
			   (int) 0, &saremote, &salen);

	if (length <= 0)
	{
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		return -1;
	}
	recv_auth = (AUTH_HDR *)recv_buffer;
	printf("recv_auth->code = %d, recv_auth->id = %d\n", recv_auth->code, recv_auth->id);
	if (recv_auth->code == 2 && recv_auth->id == 1 ) {
		printf("auth successfully\n");
	}
	else{
		printf("auth failed\n");

	}
	/*result = rc_check_reply (recv_auth, 8192, secret, vector, 1);*/

}

static int radius_acct_start(char *username)
{
	AUTH_HDR *auth, *recv_auth;
	struct sockaddr salocal; struct sockaddr saremote;
	struct sockaddr_in *sin;
	struct timeval  authtime;
	fd_set          readfds;
	char            send_buffer[BUFFER_LEN];
	char            recv_buffer[BUFFER_LEN];
	unsigned char *buf;
	unsigned char vector[AUTH_VECTOR_LEN];
	unsigned char md5buf[256];
	int sockfd;
	unsigned int length;
	unsigned char secret[49];
	unsigned int total_length = 0;
	unsigned int salen;
	unsigned char   passbuf[MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char *pw_buf, *pw_vector;

	int padded_length;
	int secretlen;
	int pc, i;

	char *session_id = username;
	int acct_status = 1;
	unsigned int lvalue;
	/*unsigned long framed_ip_addr;*/
	unsigned int framed_ip_addr;

	auth = malloc(sizeof(AUTH_HDR));
	if (auth == (AUTH_HDR *)NULL){
		printf("alloc auth failed\n");
		return -1;
	}

	auth = (AUTH_HDR *)send_buffer;
	buf = auth->data; 
	auth->code = 4;
	auth->id = 1;
	

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		printf("sockfd failed\n");
		return; 
	}

	length = sizeof (salocal);
	sin = (struct sockaddr_in *) & salocal;
	memset ((char *) sin, '\0', (size_t) length);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons ((unsigned short) 0);
	if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||
		   getsockname (sockfd, (struct sockaddr *) sin, &length) < 0)
	{
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		/*error("rc_send_server: bind: %s: %m", server_name);*/
		/*return (ERROR_RC);*/
		printf("bind error\n");
		return -1;
	}

	strcpy(secret, MGMT_POLL_SECRET);

	 /*username*/ 
	*buf++ = 1; /*username*/ 
	*buf++ = 2 + strlen(username);
	memcpy(buf, username, strlen(username));
	buf += strlen(username) ;
	total_length += 2 + strlen(username);

    /*acct-session-id*/ 
	*buf++ = 44;
	*buf++ = 2 + strlen(session_id);
	memcpy(buf, session_id, strlen(session_id));
	buf += strlen(session_id) ;
	total_length += 2 + strlen(session_id);

	/*Frame-ip-address*/ 
	*buf++ = 8;
	*buf++ = 2 + sizeof(unsigned int);
	framed_ip_addr = inet_addr("192.168.0.99");
	/*printf("the ip addr is %s %d %d\n", inet_ntoa(framed_ip_addr), sizeof(framed_ip_addr), sizeof(unsigned int));*/
	memcpy(buf, &framed_ip_addr, sizeof(unsigned int));
	buf += sizeof(unsigned int);
	total_length += 2 + sizeof(unsigned int);

    /*acct-status-type*/ 
	*buf++ = 40;
	*buf++ = 2 + sizeof(unsigned int); 
	lvalue = htonl(acct_status);
	/**buf = 1;*/
	memcpy(buf, (char *) &lvalue, sizeof(unsigned int));
	total_length += 2 + sizeof(unsigned int);

	total_length += 20;
	auth->length = htons ((unsigned short) total_length);
	memset((char *) auth->vector, 0, AUTH_VECTOR_LEN);
	secretlen = strlen (secret);
	memcpy ((char *) auth + total_length, secret, secretlen);
	rc_md5_calc (vector, (char *) auth, total_length + secretlen);
	memcpy(auth->vector, vector, AUTH_VECTOR_LEN);

	sin = (struct sockaddr_in *) & saremote;
	memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	/*sin->sin_addr.s_addr = inet_addr("192.168.0.99");*/
	sin->sin_addr.s_addr = inet_addr("115.29.203.202");
	sin->sin_port = htons(1813);

	for (;;)
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			(struct sockaddr *) sin, sizeof (struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) 1;
		FD_ZERO (&readfds);
		FD_SET (sockfd, &readfds);
		if (select (sockfd + 1, &readfds, NULL, NULL, &authtime) < 0) {
			/*if (errno == EINTR)*/
				/*continue;*/
			/*error("rc_send_server: select: %m");*/
			memset (secret, '\0', sizeof (secret));
			close (sockfd);
			return -1;
		}
		if (FD_ISSET (sockfd, &readfds))
			break;
	}
	salen = sizeof (saremote);
	length = recvfrom (sockfd, (char *) recv_buffer,
			   (int) sizeof (recv_buffer),
			   (int) 0, &saremote, &salen);

	if (length <= 0)
	{
		close (sockfd);
		memset (secret, '\0', sizeof (secret));
		return -1;
	}
	recv_auth = (AUTH_HDR *)recv_buffer;
	if (recv_auth->code == 5 && recv_auth->id == 1 ) {
		printf("acct successfully\n");
	}
	else{
		printf("acct failed\n");

	}
	/*result = rc_check_reply (recv_auth, 8192, secret, vector, 1);*/

}

int main(int argc, char **argv)
{
	char *username = "user1";
	char *passwd   = "123456";

	radius_pap_auth(username, passwd);
	radius_acct_start(username);
}


