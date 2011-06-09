/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * dalvik.system.Zygote
 */
#include "Dalvik.h"
#include "native/InternalNativePriv.h"

#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <grp.h>
#include <errno.h>

#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "PAProtocol.h"

#if defined(HAVE_PRCTL)
# include <sys/prctl.h>
#endif

#define ZYGOTE_LOG_TAG "Zygote"
#define POWER_ARBITER_SOCKPATH "/data/power_arbiter"

#define CINDER_MAX_NAMELEN 20

#define CINDER_CAP_RESERVE_DRAW   0x1
#define CINDER_CAP_RESERVE_MODIFY 0x2
#define CINDER_CAP_ALL (CINDER_CAP_RESERVE_DRAW | CINDER_CAP_RESERVE_MODIFY)

#define SYS_RESERVE_INFO 364
#define SYS_ADD_RESERVE_CHILD_LIST 378
#define SYS_DEL_RESERVE_CHILD_LIST 379
#define SYS_NUM_CHILD_LIST_RESERVES 380
#define SYS_GET_CHILD_LIST_RESERVE 381
#define SYS_ROOT_RESERVE_ID 383

const char *pa_uid_exists = "PowerArbiter: UID already exists.";
const char *pa_invalid_input = "PowerArbiter: Invalid input for operation.";
const char *pa_bad_permissions = "PowerArbiter: Bad permissions for operation.";
const char *pa_failure = "PowerArbiter: Operation failed.";
const char *pa_success = "PowerArbiter: Operation succeeded.";
const char *pa_uid_not_found = "PowerArbiter: UID mapping not found.";
const char *pa_unexpected_error = "PowerArbiter: Unexpected error condition";

/* must match values in dalvik.system.Zygote */
enum {
    DEBUG_ENABLE_DEBUGGER           = 1,
    DEBUG_ENABLE_CHECKJNI           = 1 << 1,
    DEBUG_ENABLE_ASSERT             = 1 << 2,
};

struct reserve_info {
	int id;
	long capacity, lifetime_input, lifetime_usage;
	char name[CINDER_MAX_NAMELEN];

	int num_users;

	/* TODO: Implement # taps */
	int num_process_taps;
};

long reserve_info(int reserve_id, struct reserve_info *info)
{
	return syscall(SYS_RESERVE_INFO, reserve_id, info);
}

long add_reserve_to_child_list(int reserve_id, unsigned int capabilities)
{
	return syscall(SYS_ADD_RESERVE_CHILD_LIST, reserve_id, capabilities);
}


long del_reserve_from_child_list(int reserve_id)
{
	return syscall(SYS_DEL_RESERVE_CHILD_LIST, reserve_id);
}

long num_child_list_reserves(void)
{
	return syscall(SYS_NUM_CHILD_LIST_RESERVES);
}

int get_child_list_reserve(long index)
{
	return syscall(SYS_GET_CHILD_LIST_RESERVE, index);
}

static void
__format_error_str(int err, char *buf, int buflen)
{
	if (err < 0)
		err *= -1;

    strerror_r(err, buf, buflen);
	buf[buflen - 1] = '\0';
}

static void
__power_arbiter_response_to_str(uint32_t error, char *buf, int len)
{
    if (error == PA_UID_EXISTS) {
		snprintf(buf, len, "%s", pa_uid_exists);
    }
    else if (error == PA_INVALID_INPUT) {
		snprintf(buf, len, "%s", pa_invalid_input);
    }
    else if (error == PA_BAD_PERMISSIONS) {
		snprintf(buf, len, "%s", pa_bad_permissions);
    }
    else if (error == PA_FAILURE) {
		snprintf(buf, len, "%s", pa_failure);
    }
    else if (error == PA_NO_ERROR) {
		snprintf(buf, len, "%s", pa_success);
    }
    else if (error == PA_UID_NOT_FOUND) {
		snprintf(buf, len, "%s", pa_uid_not_found);
    }
    else {
		snprintf(buf, len, "%s: %d", pa_unexpected_error, error);
    }
}

int
streamsock_read(int sock, uint8_t *buf, uint64_t bufsiz, uint64_t to_read,
	uint64_t *num_bytes_read)
{
	int err;
	ssize_t recv_ret;
	uint8_t *buf_offset = buf;
	uint64_t rcvd = 0, remaining = to_read;

	if (sock == -1 || !buf || to_read > bufsiz || !num_bytes_read)
		return -EINVAL;

	while (rcvd < to_read) {
		recv_ret = recv(sock, buf_offset, remaining, 0);
		if (recv_ret == -1) {
			// Error
			err = errno;
			return err;
		}
		if (recv_ret == 0) {
			// Orderly shutdown
			break;
		}

		rcvd += (uint64_t) recv_ret;
		remaining -= (uint64_t) recv_ret;
		buf_offset += (ptrdiff_t) recv_ret;
	}

	*num_bytes_read = rcvd;
	printf("Read %lld bytes.\n", rcvd);
	return 0;
}

int
streamsock_send(int sock, const uint8_t *buf, uint64_t to_send,
	uint64_t *num_bytes_sent)
{
	int err;
	ssize_t send_ret;
	const uint8_t *buf_offset = buf;
	uint64_t sent = 0, remaining = to_send;

	if (sock == -1 || !buf || !num_bytes_sent)
		return -EINVAL;

	while (sent < to_send) {
		send_ret = send(sock, buf_offset, remaining, 0);
		if (send_ret == -1) {
			err = errno;
			return err;
		}

		sent += (uint64_t) send_ret;
		remaining -= (uint64_t) send_ret;
		buf_offset += (ptrdiff_t) send_ret;
	}

	*num_bytes_sent = sent;
	return 0;
}

static int
__connect_to_arbiter(int *sock)
{
    int socket_fd, err;
    struct sockaddr_un address;
    socklen_t address_length;
    char buffer[256];
	char error_s[256];

    socket_fd = socket(PF_UNIX, SOCK_STREAM, 0);
    if(socket_fd < 0) {
      err = errno;
      perror("socket");
      return err;
    }

    address.sun_family = AF_UNIX;
    address_length = sizeof(address.sun_family) +
                  sprintf(address.sun_path, POWER_ARBITER_SOCKPATH);

	// TODO: Strict aliasing warning here regarding dereferencing type punned pointer
    if(connect(socket_fd, (struct sockaddr *) &address, address_length) != 0) {
        err = errno;
		__format_error_str(err, error_s, sizeof(error_s));
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Error connecting to power arbiter: [%s]\n",
                    error_s);
        return err;
    }

    *sock = socket_fd;
    return 0;
}

static int
__get_reserve_id_for_uid(uid_t uid, int socket_fd, int *rsv_id, int *use_root)
{
	int ret;
	PAStatReserveQuery query;
    PAStatReserveResponse response;
    PARequest requestType;
    uint64_t num_transferred;
	char error_s[256];

    // First set up packet
    query.uid = uid;
    requestType.request_type = PA_STAT_RESERVE;

    // Send request
    ret = streamsock_send(socket_fd, (uint8_t *)&requestType, sizeof(requestType),
        &num_transferred);
    if (ret || num_transferred != sizeof(requestType)) {
		__format_error_str(ret, error_s, sizeof(error_s));
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Error sending bytes to power arbiter: [%s]\n",
                    error_s);
        return ret;
    }

    ret = streamsock_send(socket_fd, (uint8_t *)&query, sizeof(query),
        &num_transferred);
    if (ret || num_transferred != sizeof(query)) {
		__format_error_str(ret, error_s, sizeof(error_s));
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Error sending bytes to power arbiter: [%s]\n",
                    error_s);
        return ret;
    }

    // Get response
    ret = streamsock_read(socket_fd, (uint8_t *)&response, sizeof(response), sizeof(response),
        &num_transferred);
    if (ret || num_transferred != sizeof(response)) {
		__format_error_str(ret, error_s, sizeof(error_s));
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Error receiving bytes from power arbiter: [%s]\n",
                    error_s);
        return ret;
    }

	// Log response
	__power_arbiter_response_to_str(response.error, error_s, sizeof(error_s));
	LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Power Arbiter response: [%s]\n",
                    error_s);

	// Parse response
	if (response.error == PA_NO_ERROR) {
        if (response.flags & PA_USE_ROOT_RESERVE) {
            *use_root = 1;
        }
        else if (response.flags & PA_RESERVE_GRANTED) {
			// Note this is the only case where rsv_id is valid
			*use_root = 0;
			*rsv_id = response.rid;
        }
        else {
			LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Power Arbiter response has bad flags: %d\n",
                    response.flags);
            *use_root = 1;
        }
    }
	else {
		// Some error occurred remotely
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "PowerArbiter operation failed\n");
		*use_root = 1;
	}
	// Done.
	return 0;
}

static int
__verify_reserve_access(int reserve_id)
{
	int err;
	char error_s[256];
	struct reserve_info rsv_info;

	err = (int) reserve_info(reserve_id, &rsv_info);
	if (err) {
		__format_error_str(err, error_s, sizeof(error_s));
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Verification of reserve access failed for RID %d : [%s]\n",
			reserve_id, error_s);
	}
	return err;
}

static int
__clear_child_reserve_list()
{
	int err, reserve_id;

	while (num_child_list_reserves() > 0) {
		reserve_id = get_child_list_reserve(0);
		if (reserve_id < 0)
			return reserve_id;

		err = (int) del_reserve_from_child_list(reserve_id);
		if (err)
			return err;
	}

	return 0;
}

static void
__cinder_reset_child_reserves()
{
	int err, root_reserve_id;

	// Get root reserve ID. This call cannot fail.
	root_reserve_id = syscall(SYS_ROOT_RESERVE_ID);

	// Remove all reserves from child list
	err = __clear_child_reserve_list();
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Unable to reset child reserves for zygote.\n");
	}

	// Place root reserve onto child list
	err = (int) add_reserve_to_child_list(root_reserve_id, CINDER_CAP_ALL);
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Unable to readd root reserve to zygote child list.\n");
	}
}

static void
__cinder_setup_child_reserves(uid_t uid, int *used_root)
{
	int socket_fd, err, reserve_id, use_root = 1;

	// By default we use root
	*used_root = 1;

	// Connect to arbiter
	err = __connect_to_arbiter(&socket_fd);
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Connection to power arbiter failed."
                    " Should use root reserve for child.\n");
		return;
	}

	// Get access to child reserve for UID
	err = __get_reserve_id_for_uid(uid, socket_fd, &reserve_id, &use_root);
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Unable to get reserve ID for UID %d."
                    " Should use root reserve for child.\n", uid);
		return;
	}
	if (use_root) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Using root reserve for UID %d.\n", uid);
		return;
	}

	// Verify we have access to reserve
	err = __verify_reserve_access(reserve_id);
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Unable to access reserve %d for UID %d.\n",
			reserve_id, uid);
		return;
	}

	// Clear child reserve list
	err = __clear_child_reserve_list();
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Unable to clear child reserves for UID %d.\n",
			uid);
		return;
	}

	// Add reserve to child reserve list
	err = (int) add_reserve_to_child_list(reserve_id, CINDER_CAP_ALL);
	if (err) {
		LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Unable to add reserve for UID %d.\n",
			uid);
		__cinder_reset_child_reserves();
		return;
	}
	*used_root = 0;

	// All done.
	LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Successfully set reserve when forking for UID %d.\n",
			uid);
}

/*
 * This signal handler is for zygote mode, since the zygote
 * must reap its children
 */
static void sigchldHandler(int s)
{
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        /* Log process-death status that we care about.  In general it is not
           safe to call LOG(...) from a signal handler because of possible
           reentrancy.  However, we know a priori that the current implementation
           of LOG() is safe to call from a SIGCHLD handler in the zygote process.
           If the LOG() implementation changes its locking strategy or its use
           of syscalls within the lazy-init critical section, its use here may
           become unsafe. */
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status)) {
                LOG(LOG_DEBUG, ZYGOTE_LOG_TAG, "Process %d exited cleanly (%d)\n",
                    (int) pid, WEXITSTATUS(status));
            } else {
                IF_LOGV(/*should use ZYGOTE_LOG_TAG*/) {
                    LOG(LOG_VERBOSE, ZYGOTE_LOG_TAG,
                        "Process %d exited cleanly (%d)\n",
                        (int) pid, WEXITSTATUS(status));
                }
            }
        } else if (WIFSIGNALED(status)) {
            if (WTERMSIG(status) != SIGKILL) {
                LOG(LOG_DEBUG, ZYGOTE_LOG_TAG,
                    "Process %d terminated by signal (%d)\n",
                    (int) pid, WTERMSIG(status));
            } else {
                IF_LOGV(/*should use ZYGOTE_LOG_TAG*/) {
                    LOG(LOG_VERBOSE, ZYGOTE_LOG_TAG,
                        "Process %d terminated by signal (%d)\n",
                        (int) pid, WTERMSIG(status));
                }
            }
#ifdef WCOREDUMP
            if (WCOREDUMP(status)) {
                LOG(LOG_INFO, ZYGOTE_LOG_TAG, "Process %d dumped core\n",
                    (int) pid);
            }
#endif /* ifdef WCOREDUMP */
        }

        /* 
         * If the just-crashed process is the system_server, bring down zygote
         * so that it is restarted by init and system server will be restarted
         * from there.
         */
        if (pid == gDvm.systemServerPid) {
            LOG(LOG_INFO, ZYGOTE_LOG_TAG,
                "Exit zygote because system server (%d) has terminated\n", 
                (int) pid);
            kill(getpid(), SIGKILL);
        }
    }

    if (pid < 0) {
        LOG(LOG_WARN, ZYGOTE_LOG_TAG,
            "Zygote SIGCHLD error (%d) in waitpid\n",errno);
    }
}

/*
 * configure sigchld handler for the zygote process
 * This is configured very late, because earlier in the dalvik lifecycle
 * we can fork() and exec() for the verifier/optimizer, and we
 * want to waitpid() for those rather than have them be harvested immediately.
 *
 * This ends up being called repeatedly before each fork(), but there's
 * no real harm in that.
 */
static void setSignalHandler() 
{
    int err;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = sigchldHandler;

    err = sigaction (SIGCHLD, &sa, NULL);
    
    if (err < 0) {
        LOGW("Error setting SIGCHLD handler errno: %d", errno);
    }
}

/*
 * Set the SIGCHLD handler back to default behavior in zygote children
 */
static void unsetSignalHandler()
{
    int err;
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = SIG_DFL;

    err = sigaction (SIGCHLD, &sa, NULL);
    
    if (err < 0) {
        LOGW("Error unsetting SIGCHLD handler errno: %d", errno);
    }
}

/* 
 * Calls POSIX setgroups() using the int[] object as an argument.
 * A NULL argument is tolerated.
 */

static int setgroupsIntarray(ArrayObject* gidArray)
{
    gid_t *gids;
    u4 i;
    s4 *contents;

    if (gidArray == NULL) {
        return 0;
    }

    /* just in case gid_t and u4 are different... */
    gids = alloca(sizeof(gid_t) * gidArray->length);
    contents = (s4 *)gidArray->contents;

    for (i = 0 ; i < gidArray->length ; i++) {
        gids[i] = (gid_t) contents[i];
    }

    return setgroups((size_t) gidArray->length, gids);
}

/*
 * Sets the resource limits via setrlimit(2) for the values in the
 * two-dimensional array of integers that's passed in. The second dimension
 * contains a tuple of length 3: (resource, rlim_cur, rlim_max). NULL is
 * treated as an empty array.
 *
 * -1 is returned on error.
 */
static int setrlimitsFromArray(ArrayObject* rlimits)
{
    u4 i;
    struct rlimit rlim;

    if (rlimits == NULL) {
        return 0;
    }

    memset (&rlim, 0, sizeof(rlim));

    ArrayObject** tuples = (ArrayObject **)(rlimits->contents);

    for (i = 0; i < rlimits->length; i++) {
        ArrayObject * rlimit_tuple = tuples[i];
        s4* contents = (s4 *)rlimit_tuple->contents;
        int err;

        if (rlimit_tuple->length != 3) {
            LOGE("rlimits array must have a second dimension of size 3");
            return -1;
        }

        rlim.rlim_cur = contents[1];
        rlim.rlim_max = contents[2];

        err = setrlimit(contents[0], &rlim);

        if (err < 0) {
            return -1;
        }
    }
    
    return 0;
}

/* native public static int fork(); */
static void Dalvik_dalvik_system_Zygote_fork(const u4* args, JValue* pResult)
{
    pid_t pid;
    int err;

    if (!gDvm.zygote) {
        dvmThrowException("Ljava/lang/IllegalStateException;",
            "VM instance not started with -Xzygote");

        RETURN_VOID();
    }

    if (!dvmGcPreZygoteFork()) {
        LOGE("pre-fork heap failed\n");
        dvmAbort();
    }

    setSignalHandler();      

    dvmDumpLoaderStats("zygote");
    pid = fork();

#ifdef HAVE_ANDROID_OS
    if (pid == 0) {
        /* child process */
        extern int gMallocLeakZygoteChild;
        gMallocLeakZygoteChild = 1;
    }
#endif

    RETURN_INT(pid);
}

/*
 * Enable/disable debug features requested by the caller.
 *
 * debugger
 *   If set, enable debugging; if not set, disable debugging.  This is
 *   easy to handle, because the JDWP thread isn't started until we call
 *   dvmInitAfterZygote().
 * checkjni
 *   If set, make sure "check JNI" is eabled.  This is a little weird,
 *   because we already have the JNIEnv for the main thread set up.  However,
 *   since we only have one thread at this point, it's easy to patch up.
 * assert
 *   If set, make sure assertions are enabled.  This gets fairly weird,
 *   because it affects the result of a method called by class initializers,
 *   and hence can't affect pre-loaded/initialized classes.
 */
static void enableDebugFeatures(u4 debugFlags)
{
    LOGV("debugFlags is 0x%02x\n", debugFlags);

    gDvm.jdwpAllowed = ((debugFlags & DEBUG_ENABLE_DEBUGGER) != 0);

    if ((debugFlags & DEBUG_ENABLE_CHECKJNI) != 0) {
        /* turn it on if it's not already enabled */
        dvmLateEnableCheckedJni();
    }

    if ((debugFlags & DEBUG_ENABLE_ASSERT) != 0) {
        /* turn it on if it's not already enabled */
        dvmLateEnableAssertions();
    }
}

/* 
 * Utility routine to fork zygote and specialize the child process.
 */
static pid_t forkAndSpecializeCommon(const u4* args)
{
    pid_t pid;
	int used_root = 1;

    uid_t uid = (uid_t) args[0];
    gid_t gid = (gid_t) args[1];
    ArrayObject* gids = (ArrayObject *)args[2];
    u4 debugFlags = args[3];
    ArrayObject *rlimits = (ArrayObject *)args[4];

    if (!gDvm.zygote) {
        dvmThrowException("Ljava/lang/IllegalStateException;",
            "VM instance not started with -Xzygote");

        return -1;
    }

    if (!dvmGcPreZygoteFork()) {
        LOGE("pre-fork heap failed\n");
        dvmAbort();
    }

    setSignalHandler();      

    dvmDumpLoaderStats("zygote");
	__cinder_setup_child_reserves(uid, &used_root);
    pid = fork();

    if (pid == 0) {
        int err;
        /* The child process */

#ifdef HAVE_ANDROID_OS
        extern int gMallocLeakZygoteChild;
        gMallocLeakZygoteChild = 1;

        /* keep caps across UID change, unless we're staying root */
        if (uid != 0) {
            err = prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

            if (err < 0) {
                LOGW("cannot PR_SET_KEEPCAPS errno: %d", errno);
            }
        }

#endif /* HAVE_ANDROID_OS */

        err = setgroupsIntarray(gids);

        if (err < 0) {
            LOGW("cannot setgroups() errno: %d", errno);
        }

        err = setrlimitsFromArray(rlimits);

        if (err < 0) {
            LOGW("cannot setrlimit() errno: %d", errno);
        }

        err = setgid(gid);
        if (err < 0) {
            LOGW("cannot setgid(%d) errno: %d", gid, errno);
        }

        err = setuid(uid);
        if (err < 0) {
            LOGW("cannot setuid(%d) errno: %d", uid, errno);
        }

        /*
         * Our system thread ID has changed.  Get the new one.
         */
        Thread* thread = dvmThreadSelf();
        thread->systemTid = dvmGetSysThreadId();

        /* configure additional debug options */
        enableDebugFeatures(debugFlags);

        unsetSignalHandler();      
        gDvm.zygote = false;
        if (!dvmInitAfterZygote()) {
            LOGE("error in post-zygote initialization\n");
            dvmAbort();
        }
    } else if (pid > 0) {
        /* the parent process */
		if (!used_root) {
			__cinder_reset_child_reserves();
		}
    }

    return pid;
}

/* native public static int forkAndSpecialize(int uid, int gid, 
 *     int[] gids, int debugFlags); 
 */
static void Dalvik_dalvik_system_Zygote_forkAndSpecialize(const u4* args,
    JValue* pResult)
{
    pid_t pid;

    pid = forkAndSpecializeCommon(args);

    RETURN_INT(pid);
}

/* native public static int forkSystemServer(int uid, int gid, 
 *     int[] gids, int debugFlags); 
 */
static void Dalvik_dalvik_system_Zygote_forkSystemServer(
        const u4* args, JValue* pResult)
{
    pid_t pid;
    pid = forkAndSpecializeCommon(args);

    /* The zygote process checks whether the child process has died or not. */
    if (pid > 0) {
        int status;

        LOGI("System server process %d has been created", pid);
        gDvm.systemServerPid = pid;
        /* There is a slight window that the system server process has crashed
         * but it went unnoticed because we haven't published its pid yet. So
         * we recheck here just to make sure that all is well.
         */
        if (waitpid(pid, &status, WNOHANG) == pid) {
            LOGE("System server process %d has died. Restarting Zygote!", pid);
            kill(getpid(), SIGKILL);
        }
    }
    RETURN_INT(pid);
}

const DalvikNativeMethod dvm_dalvik_system_Zygote[] = {
    { "fork",            "()I",
        Dalvik_dalvik_system_Zygote_fork },
    { "forkAndSpecialize",            "(II[II[[I)I",
        Dalvik_dalvik_system_Zygote_forkAndSpecialize },
    { "forkSystemServer",            "(II[II[[I)I",
        Dalvik_dalvik_system_Zygote_forkSystemServer },
    { NULL, NULL, NULL },
};

