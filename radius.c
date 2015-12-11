#include <sys/types.h>          /*  See NOTES */
#include <sys/socket.h>
#include <stdio.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <time.h>

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
/*#define RADIUS_ADDR	"121.41.81.117"*/
/*#define RADIUS_ADDR	"121.41.81.117"*/
/*#define RADIUS_ADDR	"121.41.81.117"*/

typedef struct pw_auth_hdr {
	u_char          code;
	u_char          id; 
	u_short         length;
	u_char          vector[AUTH_VECTOR_LEN];
	u_char          data[2];
} AUTH_HDR;

typedef struct radius_user {
	char *username;
	unsigned int id;
	int sockfd;
	int mysql_times;
	char *acctsessionid;
} RADIUS_USER;

static struct timeval tstart, tspend;
static unsigned long mysql_num = 0;
static unsigned long mysql_num_send = 0;
static pthread_mutex_t mysql_num_lock;
static float timeuse;

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

static int radius_pap_auth(RADIUS_USER *radius_user)
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
	unsigned int length;
	unsigned char secret[49];
	unsigned int total_length = 0;
	unsigned int salen;
	unsigned char   passbuf[MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char *pw_buf, *pw_vector;

	int padded_length;
	int secretlen;
	int pc, i, j;

	char *password   = "123456";
	int sockfd = radius_user->sockfd;
	char *username = radius_user->username;
	unsigned int id = radius_user->id;

	auth = malloc(sizeof(AUTH_HDR));
	if (auth == (AUTH_HDR *)NULL){
		printf("alloc auth failed\n");
		return -1;
	}

	auth = (AUTH_HDR *)send_buffer;
	buf = auth->data; 
	auth->code = 1;
	/*auth->id = id % 256;*/
	auth->id = rand()% 256;
	

	length = sizeof (salocal);
	sin = (struct sockaddr_in *) & salocal;
	memset ((char *) sin, '\0', (size_t) length);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons ((unsigned short) 0);

	/*if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||*/
		   /*getsockname (sockfd, (struct sockaddr *) sin, &length) < 0)*/
	/*{*/
		/*memset (secret, '\0', sizeof (secret));*/
		/*[>error("rc_send_server: bind: %s: %m", server_name);<]*/
		/*[>return (ERROR_RC);<]*/
		/*printf("bind error\n");*/
		/*return -1;*/
	/*}*/

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
	/*sin->sin_addr.s_addr = inet_addr("192.168.1.33");*/
	/*sin->sin_addr.s_addr = inet_addr("115.29.203.202");*/
	sin->sin_addr.s_addr = inet_addr("121.41.81.117");
	sin->sin_port = htons(1812);

	for (j = 0; j < 3; j++)
	/*for (;;)*/
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			(struct sockaddr *) sin, sizeof (struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) 5;
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
		if (FD_ISSET (sockfd, &readfds)){
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
			/*printf("recv_auth->code = %d, recv_auth->id = %d\n", recv_auth->code, recv_auth->id);*/
			if (recv_auth->code == 2 && recv_auth->id == auth->id ) {
				/*close (sockfd);*/
				/*printf("auth success: %s\n", username);*/
				return 0;
			}
			else{
				close (sockfd);
				printf("auth failed: %s\n", username);
				return -1;

			}
			/*break;*/
			return 0;
		}
	}
	printf("auth timeout %s\n", username);

	return -1;
}

static int radius_acct_start(RADIUS_USER *radius_user, bool acct)
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
	unsigned int length;
	unsigned char secret[49];
	unsigned int total_length = 0;
	unsigned int salen;
	unsigned char   passbuf[MAX(AUTH_PASS_LEN, CHAP_VALUE_LENGTH)];
	unsigned char *pw_buf, *pw_vector;

	int padded_length;
	int secretlen;
	int pc, i, j;

	int acct_status = 1;
	int inter_update = 3;
	unsigned int lvalue;
	/*unsigned long framed_ip_addr;*/
	unsigned int framed_ip_addr;
	unsigned int acct_input_octets;
	unsigned int acct_output_octets;

	int sockfd = radius_user->sockfd;
	char *username = radius_user->username;
	unsigned int id = radius_user->id;
	char *session_id = radius_user->acctsessionid;

	auth = malloc(sizeof(AUTH_HDR));
	if (auth == (AUTH_HDR *)NULL){
		printf("alloc auth failed\n");
		return -1;
	}

	auth = (AUTH_HDR *)send_buffer;
	buf = auth->data; 
	auth->code = 4;
	/*auth->id = id % 256;*/
	auth->id = rand() % 256;

	length = sizeof (salocal);
	sin = (struct sockaddr_in *) & salocal;
	memset ((char *) sin, '\0', (size_t) length);
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(INADDR_ANY);
	sin->sin_port = htons ((unsigned short) 0);
	/*if (bind (sockfd, (struct sockaddr *) sin, length) < 0 ||*/
		   /*getsockname (sockfd, (struct sockaddr *) sin, &length) < 0)*/
	/*{*/
		/*close (sockfd);*/
		/*memset (secret, '\0', sizeof (secret));*/
		/*[>error("rc_send_server: bind: %s: %m", server_name);<]*/
		/*[>return (ERROR_RC);<]*/
		/*printf("bind error\n");*/
		/*return -1;*/
	/*}*/

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
	framed_ip_addr = inet_addr("192.168.10.0") + id;
	/*printf("the ip addr is %s %d %d\n", inet_ntoa(framed_ip_addr), sizeof(framed_ip_addr), sizeof(unsigned int));*/
	memcpy(buf, &framed_ip_addr, sizeof(unsigned int));
	buf += sizeof(unsigned int);
	total_length += 2 + sizeof(unsigned int);

    /*acct-status-type*/ 
	*buf++ = 40;
	*buf++ = 2 + sizeof(unsigned int); 
	if (acct == 0) {
		lvalue = htonl(acct_status);
	}else {
		lvalue = htonl(inter_update);
	}
	/**buf = 1;*/
	memcpy(buf, (char *) &lvalue, sizeof(unsigned int));
	buf += sizeof(unsigned int);
	total_length += 2 + sizeof(unsigned int);

	/* Acct-Input-Octets*/ 
	*buf++ = 42;
	*buf++ = 2 + sizeof(unsigned int); 
	/*acct_input_octets = htonl(1000);*/
	acct_input_octets = htonl(time(NULL));
	memcpy(buf, (char *) &acct_input_octets, sizeof(unsigned int));
	buf += sizeof(unsigned int);
	total_length += 2 + sizeof(unsigned int);

	/* Acct-Output-Octets*/ 
	*buf++ = 43;
	*buf++ = 2 + sizeof(unsigned int); 
	acct_output_octets = htonl(500);
	memcpy(buf, (char *) &acct_output_octets, sizeof(unsigned int));
	buf += sizeof(unsigned int);
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
	/*sin->sin_addr.s_addr = inet_addr("192.168.1.33");*/
	/*sin->sin_addr.s_addr = inet_addr("115.29.203.202");*/
	sin->sin_addr.s_addr = inet_addr("121.41.81.117");
	sin->sin_port = htons(1813);

	for (j = 0; j < 3; j++)
	/*for (;;)*/
	{
		sendto (sockfd, (char *) auth, (unsigned int) total_length, (int) 0,
			(struct sockaddr *) sin, sizeof (struct sockaddr_in));

		authtime.tv_usec = 0L;
		authtime.tv_sec = (long) 5;
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
		if (FD_ISSET (sockfd, &readfds)){
			salen = sizeof (saremote);
			length = recvfrom (sockfd, (char *) recv_buffer,
					   (int) sizeof (recv_buffer),
					   (int) 0, &saremote, &salen);

			if (length <= 0)
			{
				close (sockfd);
				memset (secret, '\0', sizeof (secret));
				close (sockfd);
				return -1;
			}
			recv_auth = (AUTH_HDR *)recv_buffer;
			if (recv_auth->code == 5 && recv_auth->id == auth->id) {
				/*printf("acct successfully: %s\n", username);*/
				/*close (sockfd);*/
				return 0;
			} else{
				printf("acct failed: %s\n", username);
				close (sockfd);
				return -1;
			}
			return 0;
			/*break;*/
		}
	}
	printf("acct timeout %s\n", username);

	return -1;

}

static void radius_acct(unsigned int *id)
{
	char buf[10];
	char *name = "user";
	unsigned int user_id = *id;
	int sockfd;
	char *username;
	int ret;
	RADIUS_USER *radius_user;

	char acctsessionid[128];


	radius_user = malloc(sizeof(RADIUS_USER));
	if (radius_user == (RADIUS_USER*)NULL){
		printf("alloc radius user failed\n");
		return -1;
	}

	sprintf(buf, "%s%d", name, *id);
	username = buf;
	sprintf(acctsessionid, "%s-%d", username, time(NULL));
	radius_user->acctsessionid = acctsessionid;

	sockfd = socket (AF_INET, SOCK_DGRAM, 0);
	radius_user->sockfd = sockfd;
	radius_user->username = username;
	radius_user->id = id;
	radius_user->mysql_times = 0;
	if (sockfd < 0) {
		printf("sockfd failed %s\n", username);
		return; 
	}

	if (radius_pap_auth(radius_user) == 0) {
			radius_acct_start(radius_user, 0);
			pthread_mutex_lock(&mysql_num_lock);
			mysql_num_send += 2;
			mysql_num += 2;
			pthread_mutex_unlock(&mysql_num_lock);

			while(1) {
				usleep(1000 * 10);
				ret = radius_acct_start(radius_user, 1);
				radius_user->mysql_times++;
				pthread_mutex_lock(&mysql_num_lock);
				mysql_num_send++;
				if (ret == 0)
					mysql_num++;
				pthread_mutex_unlock(&mysql_num_lock);
			}
		}
}

static void stop_func(void)
{
	gettimeofday(&tspend, NULL);
	
	timeuse = 1000000*(tspend.tv_sec - tstart.tv_sec) + (tspend.tv_usec - tstart.tv_usec);
	timeuse /= 1000000;
	printf("request Sended: %d, request succeed: %d, timeuse: %f, request/second: %f, time = %d\n",mysql_num_send, mysql_num, timeuse, mysql_num/timeuse, time(NULL));
	exit(0);
}

void sigalrm_func(void)
{
	raise(SIGINT);
}

void thread_time(void)
{
	gettimeofday(&tstart, NULL);
}

int main(int argc, char **argv)
{
	int i;
	
	if (argc !=3){
		printf("Usage: ./radius user_num\n");
		return;
	}
	
	unsigned int user_num = atoi(argv[1]);
	pthread_t thread_id[user_num];
	unsigned int j[user_num];
	pthread_mutex_init(&mysql_num_lock, NULL);

	thread_time();

	signal(SIGALRM, sigalrm_func);
	alarm(atoi(argv[2]));
	signal(SIGINT, stop_func);

	for(i = 0; i < user_num; i++) {
		j[i] = i;
		if(pthread_create(&thread_id[i], NULL, (void *)radius_acct, &j[i]) < 0) {
			printf("create thread failed\n");
			continue;
		}
	}

	while(1)
	{
		sleep(5);
		/*printf("-----------\n");*/
	}

}


