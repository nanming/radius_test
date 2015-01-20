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

int main(int argc, char ** argv)
{
	AUTH_HDR *auth, *recv_auth;
	struct sockaddr salocal;
	struct sockaddr saremote;
	struct sockaddr_in *sin;
	struct timeval  authtime;
	fd_set          readfds;
	char            send_buffer[BUFFER_LEN];
	char            recv_buffer[BUFFER_LEN];
	unsigned char *buf;
	unsigned char vector[AUTH_VECTOR_LEN];
	int sockfd;
	unsigned int length;
	unsigned char * secret;
	unsigned int total_length;
	unsigned int salen;
	char *username = "hover";
	char *password = "wy815417";
	int padded_length;

	auth = malloc(sizeof(AUTH_HDR));
	if (auth == (AUTH_HDR *)NULL){
		printf("alloc auth failed\n");
		return -1;
	}

	auth = (AUTH_HDR *)send_buffer;
	buf = auth->data; 
	auth->code = 1;
	auth->id = 1;
	
	rc_random_vector(vector);
	memcpy(auth->vector, vector, AUTH_VECTOR_LEN);

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
	*buf++ = 1; /*username*/ 
	*buf++ = 2 + strlen(username);
	memcpy(buf, username, strlen(username));

	buf += strlen(username) ;

	*buf++ = 2; /*user password*/
	padded_length = (strlen(password)+(15)) & ~(15);
					/*  Record the attribute length */
	*buf++ = padded_length + 2;
	buf += strlen(password);
				      

	/**buf++ = 2 + strlen(password); [>length<] */
	/*memcpy(buf, password, strlen(password)); [><] */

	sin = (struct sockaddr_in *) & saremote;
	memset ((char *) sin, '\0', sizeof (saremote));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = inet_addr("192.168.0.72");
	sin->sin_port = htons(1812);
	total_length = 20 + 2 + 2 + strlen(username) + strlen(password);

	auth->length = htons ((unsigned short) total_length);

	for (;;)
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			(struct sockaddr *) sin, sizeof (struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) 10;
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
	if (recv_auth->code == 1 && recv_auth->id == 1 ) {
		printf("auth successfully\n");
	}
	else{
		printf("auth failed\n");

	}
	/*result = rc_check_reply (recv_auth, 8192, secret, vector, 1);*/

}


