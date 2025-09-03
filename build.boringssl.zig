const std = @import("std");

pub fn linkBoringSSL(
    b: *std.Build,
    uSockets: *std.Build.Step.Compile,
) !void {
    const target = uSockets.root_module.resolved_target.?;
    const optimize = uSockets.root_module.optimize.?;

    const boringssl = b.dependency("boringssl", .{});

    const libfipsmodule = b.addLibrary(.{
        .name = "fipsmodule",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libcpp = true,
        }),
    });

    libfipsmodule.link_function_sections = true;
    libfipsmodule.link_data_sections = true;
    libfipsmodule.link_gc_sections = true;
    libfipsmodule.root_module.addIncludePath(boringssl.path("include"));
    libfipsmodule.root_module.addCSourceFiles(.{
        .files = fipsmodule_sources,
        .root = boringssl.path(""),
    });

    libfipsmodule.root_module.addCSourceFiles(.{
        .files = gen_fipsmodule_sources,
        .root = boringssl.path(""),
        .language = .assembly_with_preprocessor,
    });

    uSockets.root_module.linkLibrary(libfipsmodule);

    const libcrypto = b.addLibrary(.{
        .name = "crypto",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    libcrypto.link_function_sections = true;
    libcrypto.link_data_sections = true;
    libcrypto.link_gc_sections = true;
    libcrypto.root_module.linkLibrary(libfipsmodule);
    libcrypto.root_module.addIncludePath(boringssl.path("include"));

    libcrypto.root_module.addCSourceFiles(.{
        .files = crypto_sources,
        .root = boringssl.path(""),
    });

    libcrypto.root_module.addCSourceFiles(.{
        .files = gen_crypto_sources,
        .root = boringssl.path(""),
        .language = .assembly_with_preprocessor,
    });

    uSockets.root_module.linkLibrary(libcrypto);

    const libssl = b.addLibrary(.{
        .name = "ssl",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    libssl.link_function_sections = true;
    libssl.link_data_sections = true;
    libssl.link_gc_sections = true;
    libssl.root_module.linkLibrary(libcrypto);
    libssl.root_module.addIncludePath(boringssl.path("include"));
    libssl.installHeadersDirectory(boringssl.path("include"), "", .{});

    libssl.root_module.addCSourceFiles(.{
        .files = ssl_sources,
        .root = boringssl.path(""),
    });

    uSockets.root_module.linkLibrary(libssl);

    const libdecrepit = b.addLibrary(.{
        .name = "decrepit",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    libdecrepit.link_function_sections = true;
    libdecrepit.link_data_sections = true;
    libdecrepit.link_gc_sections = true;
    libdecrepit.root_module.linkLibrary(libcrypto);
    libdecrepit.root_module.linkLibrary(libssl);
    libdecrepit.root_module.addIncludePath(boringssl.path("include"));

    libdecrepit.root_module.addCSourceFiles(.{
        .files = decrepit_sources,
        .root = boringssl.path(""),
    });

    uSockets.root_module.linkLibrary(libdecrepit);

    const libpki = b.addLibrary(.{
        .name = "pki",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });

    libpki.link_function_sections = true;
    libpki.link_data_sections = true;
    libpki.link_gc_sections = true;
    libpki.root_module.linkLibrary(libcrypto);
    libpki.root_module.addIncludePath(boringssl.path("include"));

    libpki.root_module.addCSourceFiles(.{
        .files = pki_sources,
        .root = boringssl.path(""),
    });

    uSockets.root_module.linkLibrary(libpki);

    const bssl = b.addLibrary(.{
        .name = "bssl",
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });

    bssl.link_function_sections = true;
    bssl.link_data_sections = true;
    bssl.link_gc_sections = true;
    bssl.root_module.linkLibrary(libssl);
    bssl.root_module.linkLibrary(libcrypto);
    bssl.root_module.addIncludePath(boringssl.path("include"));

    bssl.root_module.addCSourceFiles(.{
        .files = bssl_sources,
        .root = boringssl.path(""),
    });

    uSockets.root_module.linkLibrary(bssl);
}

const pki_sources = &.{
    "pki/path_builder.cc",
    "pki/verify_certificate_chain.cc",
    "pki/parse_name.cc",
    "pki/cert_error_id.cc",
    "pki/trust_store_collection.cc",
    "pki/verify.cc",
    "pki/signature_algorithm.cc",
    "pki/verify_name_match.cc",
    "pki/trust_store_in_memory.cc",
    "pki/mock_signature_verify_cache.cc",
    "pki/name_constraints.cc",
    "pki/parse_certificate.cc",
    "pki/common_cert_errors.cc",
    "pki/parser.cc",
    "pki/cert_error_params.cc",
    "pki/parse_values.cc",
    "pki/verify_error.cc",
    "pki/encode_values.cc",
    "pki/ip_util.cc",
    "pki/input.cc",
    "pki/trust_store.cc",
    "pki/revocation_util.cc",
    "pki/ocsp_verify_result.cc",
    "pki/verify_signed_data.cc",
    "pki/cert_issuer_source_static.cc",
    "pki/simple_path_builder_delegate.cc",
    "pki/certificate_policies.cc",
    "pki/crl.cc",
    "pki/extended_key_usage.cc",
    "pki/string_util.cc",
    "pki/cert_errors.cc",
    "pki/pem.cc",
    "pki/general_names.cc",
    "pki/parsed_certificate.cc",
    "pki/ocsp.cc",
    "pki/certificate.cc",
};

const bssl_sources = &.{
    "tool/args.cc",
    "tool/ciphers.cc",
    "tool/client.cc",
    "tool/const.cc",
    "tool/digest.cc",
    "tool/fd.cc",
    "tool/file.cc",
    "tool/generate_ech.cc",
    "tool/generate_ed25519.cc",
    "tool/genrsa.cc",
    "tool/pkcs12.cc",
    "tool/rand.cc",
    "tool/server.cc",
    "tool/sign.cc",
    "tool/speed.cc",
    "tool/transport_common.cc",
};

const ssl_sources = &.{
    "ssl/d1_pkt.cc",
    "ssl/ssl_versions.cc",
    "ssl/ssl_transcript.cc",
    "ssl/d1_both.cc",
    "ssl/tls13_enc.cc",
    "ssl/dtls_method.cc",
    "ssl/dtls_record.cc",
    "ssl/ssl_cipher.cc",
    "ssl/tls_method.cc",
    "ssl/extensions.cc",
    "ssl/tls_record.cc",
    "ssl/ssl_privkey.cc",
    "ssl/ssl_x509.cc",
    "ssl/ssl_buffer.cc",
    "ssl/s3_pkt.cc",
    "ssl/d1_srtp.cc",
    "ssl/tls13_both.cc",
    "ssl/ssl_aead_ctx.cc",
    "ssl/handshake_server.cc",
    "ssl/t1_enc.cc",
    "ssl/s3_lib.cc",
    "ssl/handoff.cc",
    "ssl/ssl_session.cc",
    "ssl/tls13_server.cc",
    "ssl/ssl_asn1.cc",
    "ssl/ssl_key_share.cc",
    "ssl/ssl_file.cc",
    "ssl/bio_ssl.cc",
    "ssl/handshake_client.cc",
    "ssl/encrypted_client_hello.cc",
    "ssl/ssl_lib.cc",
    "ssl/s3_both.cc",
    "ssl/ssl_cert.cc",
    "ssl/handshake.cc",
    "ssl/d1_lib.cc",
    "ssl/tls13_client.cc",
    "ssl/ssl_stat.cc",
    "ssl/ssl_credential.cc",
};

const crypto_sources = &.{
    "gen/crypto/err_data.cc",
    "crypto/md4/md4.cc",
    "crypto/asn1/tasn_typ.cc",
    "crypto/asn1/tasn_fre.cc",
    "crypto/asn1/tasn_dec.cc",
    "crypto/asn1/a_mbstr.cc",
    "crypto/asn1/a_int.cc",
    "crypto/asn1/asn1_par.cc",
    "crypto/asn1/asn_pack.cc",
    "crypto/asn1/a_gentm.cc",
    "crypto/asn1/f_string.cc",
    "crypto/asn1/a_strex.cc",
    "crypto/asn1/a_bool.cc",
    "crypto/asn1/a_bitstr.cc",
    "crypto/asn1/a_type.cc",
    "crypto/asn1/asn1_lib.cc",
    "crypto/asn1/a_i2d_fp.cc",
    "crypto/asn1/posix_time.cc",
    "crypto/asn1/a_strnid.cc",
    "crypto/asn1/tasn_new.cc",
    "crypto/asn1/a_utctm.cc",
    "crypto/asn1/a_time.cc",
    "crypto/asn1/a_d2i_fp.cc",
    "crypto/asn1/a_octet.cc",
    "crypto/asn1/tasn_utl.cc",
    "crypto/asn1/tasn_enc.cc",
    "crypto/asn1/a_object.cc",
    "crypto/asn1/a_dup.cc",
    "crypto/asn1/f_int.cc",
    "crypto/slhdsa/thash.cc",
    "crypto/slhdsa/wots.cc",
    "crypto/slhdsa/slhdsa.cc",
    "crypto/slhdsa/fors.cc",
    "crypto/slhdsa/merkle.cc",
    "crypto/pem/pem_x509.cc",
    "crypto/pem/pem_pkey.cc",
    "crypto/pem/pem_xaux.cc",
    "crypto/pem/pem_pk8.cc",
    "crypto/pem/pem_lib.cc",
    "crypto/pem/pem_oth.cc",
    "crypto/pem/pem_info.cc",
    "crypto/pem/pem_all.cc",
    "crypto/obj/obj.cc",
    "crypto/obj/obj_xref.cc",
    "crypto/md5/md5.cc",
    "crypto/bytestring/ber.cc",
    "crypto/bytestring/cbs.cc",
    "crypto/bytestring/asn1_compat.cc",
    "crypto/bytestring/cbb.cc",
    "crypto/bytestring/unicode.cc",
    "crypto/rc4/rc4.cc",
    "crypto/bio/hexdump.cc",
    "crypto/bio/socket.cc",
    "crypto/bio/socket_helper.cc",
    "crypto/bio/fd.cc",
    "crypto/bio/pair.cc",
    "crypto/bio/file.cc",
    "crypto/bio/bio.cc",
    "crypto/bio/bio_mem.cc",
    "crypto/bio/printf.cc",
    "crypto/bio/errno.cc",
    "crypto/bio/connect.cc",
    "crypto/des/des.cc",
    "crypto/blake2/blake2.cc",
    "crypto/ecdh_extra/ecdh_extra.cc",
    "crypto/mem.cc",
    "crypto/trust_token/trust_token.cc",
    "crypto/trust_token/voprf.cc",
    "crypto/trust_token/pmbtoken.cc",
    "crypto/crypto.cc",
    "crypto/cpu_aarch64_linux.cc",
    "crypto/chacha/chacha.cc",
    "crypto/thread_pthread.cc",
    "crypto/lhash/lhash.cc",
    "crypto/err/err.cc",
    "crypto/thread_none.cc",
    "crypto/base64/base64.cc",
    "crypto/dsa/dsa.cc",
    "crypto/dsa/dsa_asn1.cc",
    "crypto/fipsmodule/bcm.cc",
    "crypto/fipsmodule/fips_shared_support.cc",
    "crypto/buf/buf.cc",
    "crypto/rand_extra/urandom.cc",
    "crypto/rand_extra/windows.cc",
    "crypto/rand_extra/forkunsafe.cc",
    "crypto/rand_extra/getentropy.cc",
    "crypto/rand_extra/passive.cc",
    "crypto/rand_extra/fork_detect.cc",
    "crypto/rand_extra/trusty.cc",
    "crypto/rand_extra/rand_extra.cc",
    "crypto/rand_extra/ios.cc",
    "crypto/rand_extra/deterministic.cc",
    "crypto/cpu_aarch64_apple.cc",
    "crypto/keccak/keccak.cc",
    "crypto/cpu_intel.cc",
    "crypto/cpu_aarch64_openbsd.cc",
    "crypto/mlkem/mlkem.cc",
    "crypto/x509/x_x509.cc",
    "crypto/x509/v3_pmaps.cc",
    "crypto/x509/x509rset.cc",
    "crypto/x509/x_exten.cc",
    "crypto/x509/x509_txt.cc",
    "crypto/x509/x_val.cc",
    "crypto/x509/a_sign.cc",
    "crypto/x509/v3_ia5.cc",
    "crypto/x509/x_sig.cc",
    "crypto/x509/v3_genn.cc",
    "crypto/x509/x509_d2.cc",
    "crypto/x509/x509_v3.cc",
    "crypto/x509/a_verify.cc",
    "crypto/x509/x_attrib.cc",
    "crypto/x509/x509_trs.cc",
    "crypto/x509/v3_alt.cc",
    "crypto/x509/x509_vpm.cc",
    "crypto/x509/x_all.cc",
    "crypto/x509/x_crl.cc",
    "crypto/x509/x509_def.cc",
    "crypto/x509/t_crl.cc",
    "crypto/x509/by_dir.cc",
    "crypto/x509/x509_lu.cc",
    "crypto/x509/v3_extku.cc",
    "crypto/x509/x_algor.cc",
    "crypto/x509/v3_purp.cc",
    "crypto/x509/v3_akey.cc",
    "crypto/x509/v3_enum.cc",
    "crypto/x509/x509spki.cc",
    "crypto/x509/i2d_pr.cc",
    "crypto/x509/x509name.cc",
    "crypto/x509/v3_lib.cc",
    "crypto/x509/v3_info.cc",
    "crypto/x509/t_req.cc",
    "crypto/x509/x_req.cc",
    "crypto/x509/v3_bitst.cc",
    "crypto/x509/x_x509a.cc",
    "crypto/x509/x509_ext.cc",
    "crypto/x509/v3_ocsp.cc",
    "crypto/x509/name_print.cc",
    "crypto/x509/v3_int.cc",
    "crypto/x509/by_file.cc",
    "crypto/x509/v3_ncons.cc",
    "crypto/x509/x509_req.cc",
    "crypto/x509/v3_bcons.cc",
    "crypto/x509/asn1_gen.cc",
    "crypto/x509/x509_vfy.cc",
    "crypto/x509/v3_crld.cc",
    "crypto/x509/policy.cc",
    "crypto/x509/x509_set.cc",
    "crypto/x509/rsa_pss.cc",
    "crypto/x509/v3_prn.cc",
    "crypto/x509/x509_cmp.cc",
    "crypto/x509/v3_skey.cc",
    "crypto/x509/v3_akeya.cc",
    "crypto/x509/x509cset.cc",
    "crypto/x509/algorithm.cc",
    "crypto/x509/x_pubkey.cc",
    "crypto/x509/a_digest.cc",
    "crypto/x509/t_x509a.cc",
    "crypto/x509/x509.cc",
    "crypto/x509/x_name.cc",
    "crypto/x509/x509_obj.cc",
    "crypto/x509/v3_utl.cc",
    "crypto/x509/t_x509.cc",
    "crypto/x509/v3_cpols.cc",
    "crypto/x509/x509_att.cc",
    "crypto/x509/v3_conf.cc",
    "crypto/x509/x_spki.cc",
    "crypto/x509/v3_pcons.cc",
    "crypto/mldsa/mldsa.cc",
    "crypto/cipher_extra/e_chacha20poly1305.cc",
    "crypto/cipher_extra/derive_key.cc",
    "crypto/cipher_extra/e_rc4.cc",
    "crypto/cipher_extra/tls_cbc.cc",
    "crypto/cipher_extra/e_tls.cc",
    "crypto/cipher_extra/e_aesgcmsiv.cc",
    "crypto/cipher_extra/e_null.cc",
    "crypto/cipher_extra/e_des.cc",
    "crypto/cipher_extra/cipher_extra.cc",
    "crypto/cipher_extra/e_rc2.cc",
    "crypto/cipher_extra/e_aesctrhmac.cc",
    "crypto/bn_extra/convert.cc",
    "crypto/bn_extra/bn_asn1.cc",
    "crypto/poly1305/poly1305_vec.cc",
    "crypto/poly1305/poly1305.cc",
    "crypto/poly1305/poly1305_arm.cc",
    "crypto/rsa_extra/rsa_asn1.cc",
    "crypto/rsa_extra/rsa_print.cc",
    "crypto/rsa_extra/rsa_extra.cc",
    "crypto/rsa_extra/rsa_crypt.cc",
    "crypto/ex_data.cc",
    "crypto/cpu_aarch64_win.cc",
    "crypto/ecdsa_extra/ecdsa_asn1.cc",
    "crypto/evp/sign.cc",
    "crypto/evp/evp_ctx.cc",
    "crypto/evp/p_ec_asn1.cc",
    "crypto/evp/p_dh_asn1.cc",
    "crypto/evp/p_ed25519.cc",
    "crypto/evp/p_dsa_asn1.cc",
    "crypto/evp/print.cc",
    "crypto/evp/p_rsa.cc",
    "crypto/evp/p_dh.cc",
    "crypto/evp/p_hkdf.cc",
    "crypto/evp/p_ed25519_asn1.cc",
    "crypto/evp/p_x25519.cc",
    "crypto/evp/p_rsa_asn1.cc",
    "crypto/evp/evp_asn1.cc",
    "crypto/evp/pbkdf.cc",
    "crypto/evp/scrypt.cc",
    "crypto/evp/evp.cc",
    "crypto/evp/p_x25519_asn1.cc",
    "crypto/evp/p_ec.cc",
    "crypto/cpu_arm_linux.cc",
    "crypto/digest_extra/digest_extra.cc",
    "crypto/sha/sha256.cc",
    "crypto/sha/sha1.cc",
    "crypto/sha/sha512.cc",
    "crypto/cpu_aarch64_sysreg.cc",
    "crypto/stack/stack.cc",
    "crypto/siphash/siphash.cc",
    "crypto/kyber/kyber.cc",
    "crypto/curve25519/curve25519.cc",
    "crypto/curve25519/spake25519.cc",
    "crypto/curve25519/curve25519_64_adx.cc",
    "crypto/refcount.cc",
    "crypto/hrss/hrss.cc",
    "crypto/thread_win.cc",
    "crypto/hpke/hpke.cc",
    "crypto/conf/conf.cc",
    "crypto/engine/engine.cc",
    "crypto/pool/pool.cc",
    "crypto/pkcs7/pkcs7_x509.cc",
    "crypto/pkcs7/pkcs7.cc",
    "crypto/dh_extra/dh_asn1.cc",
    "crypto/dh_extra/params.cc",
    "crypto/cpu_aarch64_fuchsia.cc",
    "crypto/thread.cc",
    "crypto/cpu_arm_freebsd.cc",
    "crypto/pkcs8/p5_pbev2.cc",
    "crypto/pkcs8/pkcs8.cc",
    "crypto/pkcs8/pkcs8_x509.cc",
    "crypto/ec_extra/ec_asn1.cc",
    "crypto/ec_extra/hash_to_curve.cc",
    "crypto/ec_extra/ec_derive.cc",
};

const decrepit_sources = &.{
    "decrepit/obj/obj_decrepit.cc",
    "decrepit/rc4/rc4_decrepit.cc",
    "decrepit/ssl/ssl_decrepit.cc",
    "decrepit/bio/base64_bio.cc",
    "decrepit/des/cfb64ede.cc",
    "decrepit/dh/dh_decrepit.cc",
    "decrepit/blowfish/blowfish.cc",
    "decrepit/xts/xts.cc",
    "decrepit/cast/cast.cc",
    "decrepit/cast/cast_tables.cc",
    "decrepit/rsa/rsa_decrepit.cc",
    "decrepit/dsa/dsa_decrepit.cc",
    "decrepit/x509/x509_decrepit.cc",
    "decrepit/evp/evp_do_all.cc",
    "decrepit/evp/dss1.cc",
    "decrepit/cfb/cfb.cc",
    "decrepit/ripemd/ripemd.cc",
};

const fipsmodule_sources = &.{
    "crypto/fipsmodule/bcm.cc",
    "crypto/fipsmodule/fips_shared_support.cc",
};

const gen_fipsmodule_sources = &.{
    "gen/bcm/aesni-gcm-x86_64-apple.S",
    "gen/bcm/aesni-gcm-x86_64-linux.S",
    "gen/bcm/aesni-x86_64-apple.S",
    "gen/bcm/aesni-x86_64-linux.S",
    "gen/bcm/aesni-x86-apple.S",
    "gen/bcm/aesni-x86-linux.S",
    "gen/bcm/aesv8-armv7-linux.S",
    "gen/bcm/aesv8-armv8-apple.S",
    "gen/bcm/aesv8-armv8-linux.S",
    "gen/bcm/aesv8-armv8-win.S",
    "gen/bcm/aesv8-gcm-armv8-apple.S",
    "gen/bcm/aesv8-gcm-armv8-linux.S",
    "gen/bcm/aesv8-gcm-armv8-win.S",
    "gen/bcm/armv4-mont-linux.S",
    "gen/bcm/armv8-mont-apple.S",
    "gen/bcm/armv8-mont-linux.S",
    "gen/bcm/armv8-mont-win.S",
    "gen/bcm/bn-586-apple.S",
    "gen/bcm/bn-586-linux.S",
    "gen/bcm/bn-armv8-apple.S",
    "gen/bcm/bn-armv8-linux.S",
    "gen/bcm/bn-armv8-win.S",
    "gen/bcm/bsaes-armv7-linux.S",
    "gen/bcm/co-586-apple.S",
    "gen/bcm/co-586-linux.S",
    "gen/bcm/ghash-armv4-linux.S",
    "gen/bcm/ghash-neon-armv8-apple.S",
    "gen/bcm/ghash-neon-armv8-linux.S",
    "gen/bcm/ghash-neon-armv8-win.S",
    "gen/bcm/ghash-ssse3-x86_64-apple.S",
    "gen/bcm/ghash-ssse3-x86_64-linux.S",
    "gen/bcm/ghash-ssse3-x86-apple.S",
    "gen/bcm/ghash-ssse3-x86-linux.S",
    "gen/bcm/ghash-x86_64-apple.S",
    "gen/bcm/ghash-x86_64-linux.S",
    "gen/bcm/ghash-x86-apple.S",
    "gen/bcm/ghash-x86-linux.S",
    "gen/bcm/ghashv8-armv7-linux.S",
    "gen/bcm/ghashv8-armv8-apple.S",
    "gen/bcm/ghashv8-armv8-linux.S",
    "gen/bcm/ghashv8-armv8-win.S",
    "gen/bcm/p256_beeu-armv8-asm-apple.S",
    "gen/bcm/p256_beeu-armv8-asm-linux.S",
    "gen/bcm/p256_beeu-armv8-asm-win.S",
    "gen/bcm/p256_beeu-x86_64-asm-apple.S",
    "gen/bcm/p256_beeu-x86_64-asm-linux.S",
    "gen/bcm/p256-armv8-asm-apple.S",
    "gen/bcm/p256-armv8-asm-linux.S",
    "gen/bcm/p256-armv8-asm-win.S",
    "gen/bcm/p256-x86_64-asm-apple.S",
    "gen/bcm/p256-x86_64-asm-linux.S",
    "gen/bcm/rdrand-x86_64-apple.S",
    "gen/bcm/rdrand-x86_64-linux.S",
    "gen/bcm/rsaz-avx2-apple.S",
    "gen/bcm/rsaz-avx2-linux.S",
    "gen/bcm/sha1-586-apple.S",
    "gen/bcm/sha1-586-linux.S",
    "gen/bcm/sha1-armv4-large-linux.S",
    "gen/bcm/sha1-armv8-apple.S",
    "gen/bcm/sha1-armv8-linux.S",
    "gen/bcm/sha1-armv8-win.S",
    "gen/bcm/sha1-x86_64-apple.S",
    "gen/bcm/sha1-x86_64-linux.S",
    "gen/bcm/sha256-586-apple.S",
    "gen/bcm/sha256-586-linux.S",
    "gen/bcm/sha256-armv4-linux.S",
    "gen/bcm/sha256-armv8-apple.S",
    "gen/bcm/sha256-armv8-linux.S",
    "gen/bcm/sha256-armv8-win.S",
    "gen/bcm/sha256-x86_64-apple.S",
    "gen/bcm/sha256-x86_64-linux.S",
    "gen/bcm/sha512-586-apple.S",
    "gen/bcm/sha512-586-linux.S",
    "gen/bcm/sha512-armv4-linux.S",
    "gen/bcm/sha512-armv8-apple.S",
    "gen/bcm/sha512-armv8-linux.S",
    "gen/bcm/sha512-armv8-win.S",
    "gen/bcm/sha512-x86_64-apple.S",
    "gen/bcm/sha512-x86_64-linux.S",
    "gen/bcm/vpaes-armv7-linux.S",
    "gen/bcm/vpaes-armv8-apple.S",
    "gen/bcm/vpaes-armv8-linux.S",
    "gen/bcm/vpaes-armv8-win.S",
    "gen/bcm/vpaes-x86_64-apple.S",
    "gen/bcm/vpaes-x86_64-linux.S",
    "gen/bcm/vpaes-x86-apple.S",
    "gen/bcm/vpaes-x86-linux.S",
    "gen/bcm/x86_64-mont-apple.S",
    "gen/bcm/x86_64-mont-linux.S",
    "gen/bcm/x86_64-mont5-apple.S",
    "gen/bcm/x86_64-mont5-linux.S",
    "gen/bcm/x86-mont-apple.S",
    "gen/bcm/x86-mont-linux.S",
};

const gen_crypto_sources = &.{
    "gen/crypto/aes128gcmsiv-x86_64-apple.S",
    "gen/crypto/aes128gcmsiv-x86_64-linux.S",
    "gen/crypto/chacha-armv4-linux.S",
    "gen/crypto/chacha-armv8-apple.S",
    "gen/crypto/chacha-armv8-linux.S",
    "gen/crypto/chacha-armv8-win.S",
    "gen/crypto/chacha-x86_64-apple.S",
    "gen/crypto/chacha-x86_64-linux.S",
    "gen/crypto/chacha-x86-apple.S",
    "gen/crypto/chacha-x86-linux.S",
    "gen/crypto/chacha20_poly1305_armv8-apple.S",
    "gen/crypto/chacha20_poly1305_armv8-linux.S",
    "gen/crypto/chacha20_poly1305_armv8-win.S",
    "gen/crypto/chacha20_poly1305_x86_64-apple.S",
    "gen/crypto/chacha20_poly1305_x86_64-linux.S",
    "gen/crypto/md5-586-apple.S",
    "gen/crypto/md5-586-linux.S",
    "gen/crypto/md5-x86_64-apple.S",
    "gen/crypto/md5-x86_64-linux.S",

    "third_party/fiat/asm/fiat_curve25519_adx_mul.S",
    "third_party/fiat/asm/fiat_curve25519_adx_square.S",
    "third_party/fiat/asm/fiat_p256_adx_mul.S",
    "third_party/fiat/asm/fiat_p256_adx_sqr.S",
};
