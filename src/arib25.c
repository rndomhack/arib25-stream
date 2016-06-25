#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <signal.h>

#include <arib25/arib_std_b25.h>
#include <arib25/b_cas_card.h>

typedef struct {
    int32_t round;
    int32_t strip;
    int32_t emm;
} OPTIONS;

typedef struct {
    int32_t multi2_round;
    int32_t strip;
    int32_t emm_proc_on;

    int32_t unit_size;
} ARIB_STD_B25_PRIVATE_DATA_SHORT;

static bool received = false;

static void signal_handler(int sig);
static bool set_signal(int sig);
static bool parse_arg(OPTIONS *opts, int argc, char **argv);
static bool decode(OPTIONS *opts);

int main(int argc, char **argv)
{
    OPTIONS opts;

    if (!set_signal(SIGINT) || !set_signal(SIGTERM)) {
                return 1;
        }

    if (!parse_arg(&opts, argc, argv)) {
        return 1;
    }

    if (!decode(&opts)) {
        return 1;
    }

    fprintf(stderr, "exit\n");

    return 0;
}

static void signal_handler(int sig)
{
    fprintf(stderr, "signal - received\n");
    received = true;
}

static bool set_signal(int sig)
{
    if (signal(sig, signal_handler) == SIG_ERR) {
        fprintf(stderr, "error - setting signal\n");
        return false;
    }

    return true;
}

static bool parse_arg(OPTIONS *opts, int argc, char **argv)
{
    opts->round = 4;
    opts->strip = 0;
    opts->emm = 0;

    for (int i = 1; i < argc; i++) {
        if (argv[i][0] != '-') {
            break;
        }

        switch (argv[i][1]) {
            case 'm':
                if (argv[i][2]) {
                    opts->emm = atoi(argv[i] + 2);
                }
                else {
                    opts->emm = atoi(argv[i + 1]);
                    i += 1;
                }
                break;

            case 'r':
                if (argv[i][2]) {
                    opts->round = atoi(argv[i] + 2);
                }
                else {
                    opts->round = atoi(argv[i + 1]);
                    i += 1;
                }
                break;

            case 's':
                if (argv[i][2]) {
                    opts->strip = atoi(argv[i] + 2);
                }
                else {
                    opts->strip = atoi(argv[i + 1]);
                    i += 1;
                }
                break;

            default:
                fprintf(stderr, "error - unknown option '-%c'\n", argv[i][1]);
                return false;
            }
    }

    return true;
}

static bool decode(OPTIONS *opts)
{
    int i, code;
    int sfd, dfd;

    uint8_t data[64 * 1024];

    ARIB_STD_B25 *b25;
    B_CAS_CARD *bcas;

    ARIB_STD_B25_PRIVATE_DATA_SHORT *prv;

    ARIB_STD_B25_BUFFER sbuf;
    ARIB_STD_B25_BUFFER dbuf;

    // init
    sfd = 0;
    dfd = 1;

    b25 = NULL;
    bcas = NULL;

    b25 = create_arib_std_b25();
    if (b25 == NULL) {
        fprintf(stderr, "error - failed on create_arib_std_b25()\n");
        goto ERROR;
    }

    code = b25->set_multi2_round(b25, opts->round);
    if (code < 0) {
        fprintf(stderr, "error - failed on ARIB_STD_B25::set_multi2_round() : code=%d\n", code);
        goto ERROR;
    }

    code = b25->set_strip(b25, opts->strip);
    if (code < 0) {
        fprintf(stderr, "error - failed on ARIB_STD_B25::set_strip() : code=%d\n", code);
        goto ERROR;
    }

    code = b25->set_emm_proc(b25, opts->emm);
    if (code < 0) {
        fprintf(stderr, "error - failed on ARIB_STD_B25::set_emm_proc() : code=%d\n", code);
        goto ERROR;
    }

    bcas = create_b_cas_card();
    if (bcas == NULL) {
        fprintf(stderr, "error - failed on create_b_cas_card()\n");
        goto ERROR;
    }

    code = bcas->init(bcas);
    if (code < 0) {
        fprintf(stderr, "error - failed on B_CAS_CARD::init() : code=%d\n", code);
        goto ERROR;
    }

    code = b25->set_b_cas_card(b25, bcas);
    if (code < 0) {
        fprintf(stderr, "error - failed on ARIB_STD_B25::set_b_cas_card() : code=%d\n", code);
        goto ERROR;
    }

    prv = (ARIB_STD_B25_PRIVATE_DATA_SHORT *)b25->private_data;
    if (prv == NULL) {
            fprintf(stderr, "error - failed on getting private_data\n", code);
            goto ERROR;
    }

    prv->unit_size = 188;

    // decode
    while (!received && (i = read(sfd, data, sizeof(data))) > 0) {
        sbuf.data = data;
        sbuf.size = i;

        code = b25->put(b25, &sbuf);
        if (code < 0) {
            fprintf(stderr, "error - failed on ARIB_STD_B25::put() : code=%d\n", code);
            goto ERROR;
        }

        code = b25->get(b25, &dbuf);
        if (code < 0) {
            fprintf(stderr, "error - failed on ARIB_STD_B25::get() : code=%d\n", code);
            goto ERROR;
        }

        if (dbuf.size > 0) {
            i = write(dfd, dbuf.data, dbuf.size);

            if (i != dbuf.size) {
                fprintf(stderr, "error failed on _write(%d)\n", dbuf.size);
                goto ERROR;
            }
        }
    }

    // flush
    code = b25->flush(b25);
    if (code < 0) {
        fprintf(stderr, "error - failed on ARIB_STD_B25::flush() : code=%d\n", code);
        goto ERROR;
    }

    code = b25->get(b25, &dbuf);
    if (code < 0) {
        fprintf(stderr, "error - failed on ARIB_STD_B25::get() : code=%d\n", code);
        goto ERROR;
    }

    if (dbuf.size > 0) {
        i = _write(dfd, dbuf.data, dbuf.size);

        if (i != dbuf.size) {
            fprintf(stderr, "error - failed on _write(%d)\n", dbuf.size);
            goto ERROR;
        }
    }

    if (!b25) {
        b25->release(b25);
        b25 = NULL;
    }

    if (!bcas) {
        bcas->release(bcas);
        bcas = NULL;
    }

    return true;

ERROR:
    if (!b25) {
        b25->release(b25);
        b25 = NULL;
    }

    if (!bcas) {
        bcas->release(bcas);
        bcas = NULL;
    }

    return false;
}
