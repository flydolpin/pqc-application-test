#!/bin/bash
# Apply ML-DSA TLS certificate support patch to OpenSSL 3.5.4
# Usage: apply_mldsa_patch.sh <openssl_source_dir>

set -e
SRCDIR="${1:-.}"

echo "=== Applying ML-DSA TLS certificate support patch ==="

# 1. ssl/ssl_local.h - Add SSL_aPQC mask
echo "Patching ssl/ssl_local.h..."
sed -i '/^# define SSL_aGOST12             0x00000080U$/a\
/* PQC signature auth (ML-DSA) */\
# define SSL_aPQC                0x00000100U' "$SRCDIR/ssl/ssl_local.h"

# Update SSL_aCERT to include SSL_aPQC
sed -i 's/(SSL_aRSA | SSL_aDSS | SSL_aECDSA | SSL_aGOST01 | SSL_aGOST12)/(SSL_aRSA | SSL_aDSS | SSL_aECDSA | SSL_aGOST01 | SSL_aGOST12 | SSL_aPQC)/' "$SRCDIR/ssl/ssl_local.h"

# Add SSL_PKEY_ML_DSA_* indices
sed -i '/^# define SSL_PKEY_ED448          8$/a\
# define SSL_PKEY_ML_DSA_44      9\n# define SSL_PKEY_ML_DSA_65      10\n# define SSL_PKEY_ML_DSA_87      11' "$SRCDIR/ssl/ssl_local.h"

# Update SSL_PKEY_NUM
sed -i 's/^# define SSL_PKEY_NUM            9$/# define SSL_PKEY_NUM            12/' "$SRCDIR/ssl/ssl_local.h"

# 2. ssl/ssl_cert_table.h - Add ML-DSA entries
echo "Patching ssl/ssl_cert_table.h..."
# Replace the last entry (ED448 without comma) with ED448+comma and add ML-DSA entries
python3 -c "
import re
with open('$SRCDIR/ssl/ssl_cert_table.h', 'r') as f:
    content = f.read()
# Add comma after ED448 line and append ML-DSA entries
content = content.replace(
    '    {EVP_PKEY_ED448, SSL_aECDSA} /* SSL_PKEY_ED448 */\n};',
    '    {EVP_PKEY_ED448, SSL_aECDSA}, /* SSL_PKEY_ED448 */\n    {EVP_PKEY_ML_DSA_44, SSL_aPQC}, /* SSL_PKEY_ML_DSA_44 */\n    {EVP_PKEY_ML_DSA_65, SSL_aPQC}, /* SSL_PKEY_ML_DSA_65 */\n    {EVP_PKEY_ML_DSA_87, SSL_aPQC}  /* SSL_PKEY_ML_DSA_87 */\n};'
)
with open('$SRCDIR/ssl/ssl_cert_table.h', 'w') as f:
    f.write(content)
"

# 3. ssl/t1_lib.c - Add ML-DSA sigalg entries after ED448
echo "Patching ssl/t1_lib.c..."
python3 -c "
with open('$SRCDIR/ssl/t1_lib.c', 'r') as f:
    content = f.read()

# Add ML-DSA entries to sigalg_lookup_tbl after ED448 entry
mldsa_sigalg_entries = '''
    /* ML-DSA PQC signatures - pure signature, no hash (like Ed25519) */
    {TLSEXT_SIGALG_mldsa44_name,
     NULL, TLSEXT_SIGALG_mldsa44,
     NID_undef, -1, EVP_PKEY_ML_DSA_44, SSL_PKEY_ML_DSA_44,
     NID_undef, NID_undef, 1, 0,
     TLS1_3_VERSION, 0, -1, -1},
    {TLSEXT_SIGALG_mldsa65_name,
     NULL, TLSEXT_SIGALG_mldsa65,
     NID_undef, -1, EVP_PKEY_ML_DSA_65, SSL_PKEY_ML_DSA_65,
     NID_undef, NID_undef, 1, 0,
     TLS1_3_VERSION, 0, -1, -1},
    {TLSEXT_SIGALG_mldsa87_name,
     NULL, TLSEXT_SIGALG_mldsa87,
     NID_undef, -1, EVP_PKEY_ML_DSA_87, SSL_PKEY_ML_DSA_87,
     NID_undef, NID_undef, 1, 0,
     TLS1_3_VERSION, 0, -1, -1},
'''
# Find the ED448 entry block and add ML-DSA after it
ed448_end = '     TLS1_2_VERSION, 0, DTLS1_2_VERSION, 0},'
# Find second occurrence (in sigalg_lookup_tbl, not tls_default_sigalg)
parts = content.split(ed448_end)
if len(parts) >= 2:
    content = ed448_end.join([parts[0], mldsa_sigalg_entries + parts[1]] + parts[2:])

# Add ML-DSA entries to tls_default_sigalg
default_end = '    0, /* SSL_PKEY_ED448 */\n};'
default_new = '''    0, /* SSL_PKEY_ED448 */
    TLSEXT_SIGALG_mldsa44, /* SSL_PKEY_ML_DSA_44 */
    TLSEXT_SIGALG_mldsa65, /* SSL_PKEY_ML_DSA_65 */
    TLSEXT_SIGALG_mldsa87, /* SSL_PKEY_ML_DSA_87 */
};'''
content = content.replace(default_end, default_new)

with open('$SRCDIR/ssl/t1_lib.c', 'w') as f:
    f.write(content)
"

# 4. ssl/t1_lib.c - Fix ssl_setup_sigalgs for provider-only algorithms
echo "Patching ssl_setup_sigalgs for provider-only algorithms..."
python3 -c "
with open('$SRCDIR/ssl/t1_lib.c', 'r') as f:
    content = f.read()

# Replace the EVP_PKEY_set_type check with a version that falls back
# to EVP_PKEY_CTX_new_from_name for provider-only algorithms like ML-DSA
old_check = '''        if (!EVP_PKEY_set_type(tmpkey, lu->sig)) {
            cache[i].available = 0;
            continue;
        }
        pctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, tmpkey, ctx->propq);'''

new_check = '''        if (!EVP_PKEY_set_type(tmpkey, lu->sig)) {
            /*
             * For provider-only algorithms (e.g., ML-DSA) that have no legacy
             * ASN1 method, EVP_PKEY_set_type fails. Try name-based lookup
             * instead to check if a provider supports this signature algorithm.
             */
            EVP_PKEY_CTX *prov_pctx;
            const char *algname = OBJ_nid2sn(lu->sig);

            if (algname == NULL) {
                cache[i].available = 0;
                continue;
            }
            prov_pctx = EVP_PKEY_CTX_new_from_name(ctx->libctx, algname,
                                                    ctx->propq);
            if (prov_pctx == NULL) {
                cache[i].available = 0;
                continue;
            }
            EVP_PKEY_CTX_free(prov_pctx);
            cache[i].available = 1;
            continue;
        }
        pctx = EVP_PKEY_CTX_new_from_pkey(ctx->libctx, tmpkey, ctx->propq);'''

content = content.replace(old_check, new_check)

with open('$SRCDIR/ssl/t1_lib.c', 'w') as f:
    f.write(content)
"

echo "=== Patch applied successfully ==="
echo ""
echo "Verifying changes..."
grep -c "ML_DSA" "$SRCDIR/ssl/ssl_cert_table.h" || echo "WARNING: ML_DSA not found in ssl_cert_table.h"
grep -c "SSL_aPQC" "$SRCDIR/ssl/ssl_local.h" || echo "WARNING: SSL_aPQC not found in ssl_local.h"
grep -c "SSL_PKEY_ML_DSA" "$SRCDIR/ssl/ssl_local.h" || echo "WARNING: SSL_PKEY_ML_DSA not found in ssl_local.h"
grep -c "mldsa44_name" "$SRCDIR/ssl/t1_lib.c" || echo "WARNING: mldsa44 not found in t1_lib.c"
