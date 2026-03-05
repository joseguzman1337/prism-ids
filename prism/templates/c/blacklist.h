#pragma once

#define MD5_HASH_LEN 16
#define SHA1_HASH_LEN 20

#define JA3_HASH_LEN MD5_HASH_LEN
#define CERT_FINGERPRINT_LEN SHA1_HASH_LEN

/* to be used in alerts, make sure no other rules uses these values */
/* JA3 is dead... */
/* #define CL_JA3_RULE_SID 79000001 */
/* #define SV_JA3_RULE_SID 79000002 */
#define SV_CERT_RULE_SID 79000003
#define PRISM_BLACKLIST_SIDS 1

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

typedef uint8_t ja3_hash_t[JA3_HASH_LEN];
typedef uint8_t cert_fingerprint_t[CERT_FINGERPRINT_LEN];

static const cert_fingerprint_t cert_blacklist[] = {
// for fingerprint in cert_blacklist|sorted
	{/*{fingerprint|map('hex')|join(', ')}*/}/*{"," if not loop.last else ""}*/
// endfor
};

#define CERT_BLACKLIST_LEN ARRAY_SIZE(cert_blacklist)
