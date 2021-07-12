package net.schmizz.sshj.transport.verification

import com.hierynomus.sshj.userauth.keyprovider.OpenSSHKeyFileUtil
import spock.lang.Specification
import spock.lang.Unroll

import java.nio.file.Files
import java.util.regex.Pattern

/**
 * This is a comprehensive test for @cert-authority records.
 *
 * Also, take a look at the integration test {@link com.hierynomus.sshj.signature.KeyWithCertificateSpec}
 * verifying that some of that keys can be really accepted when served by sshd.
 */
class OpenSSHKnownHostsSignatureSpec extends Specification {
    @Unroll
    def "accepting a signed host public key with type #hostKeyAlgo"() {
        given:
        File knownHosts = Files.createTempFile("known_hosts", "").toFile()
        knownHosts.deleteOnExit()

        and:
        def matcher = Pattern.compile("^.*_signed_by_([^_]+)\$").matcher(hostKeyAlgo)
        assert matcher.matches()
        File caPubKey = new File("src/itest/resources/keyfiles/certificates/CA_${matcher.group(1)}.pem.pub")
        String knownHostsFileContents = "@cert-authority 127.0.0.1 " + caPubKey.getText()
        //String knownHostsFileContents = "@cert-authority localhost " + caPubKey.getText()
        knownHosts.write(knownHostsFileContents)

        and:
        def verifier = new OpenSSHKnownHosts(knownHosts)

        and:
        def publicKey = OpenSSHKeyFileUtil
                .initPubKey(new FileReader(
                        new File("src/itest/resources/keyfiles/certificates/${hostKeyAlgo}_host-cert.pub")))
                .pubKey

        when:
        boolean result = verifier.verify("127.0.0.1", 22, publicKey)

        then:
        result

        where:
        hostKeyAlgo << [
//                "id_ecdsa_256_pem_signed_by_ecdsa",
//                "id_ecdsa_256_pem_signed_by_ed25519",
//                "id_ecdsa_256_pem_signed_by_rsa",
//                "id_ecdsa_256_rfc4716_signed_by_ecdsa",
//                "id_ecdsa_256_rfc4716_signed_by_ed25519",
//                "id_ecdsa_256_rfc4716_signed_by_rsa",
//                "id_ecdsa_384_pem_signed_by_ecdsa",
//                "id_ecdsa_384_pem_signed_by_ed25519",
//                "id_ecdsa_384_pem_signed_by_rsa",
//                "id_ecdsa_384_rfc4716_signed_by_ecdsa",
//                "id_ecdsa_384_rfc4716_signed_by_ed25519",
//                "id_ecdsa_384_rfc4716_signed_by_rsa",
//                "id_ecdsa_521_pem_signed_by_ecdsa",
//                "id_ecdsa_521_pem_signed_by_ed25519",
//                "id_ecdsa_521_pem_signed_by_rsa",
//                "id_ecdsa_521_rfc4716_signed_by_ecdsa",
//                "id_ecdsa_521_rfc4716_signed_by_ed25519",
//                "id_ecdsa_521_rfc4716_signed_by_rsa",
//                "id_ed25519_384_pem_signed_by_ecdsa",
//                "id_ed25519_384_pem_signed_by_ed25519",
//                "id_ed25519_384_pem_signed_by_rsa",
//                "id_ed25519_384_rfc4716_signed_by_ecdsa",
//                "id_ed25519_384_rfc4716_signed_by_ed25519",
//                "id_ed25519_384_rfc4716_signed_by_rsa",
//                "id_rsa_2048_pem_signed_by_ecdsa",
//                "id_rsa_2048_pem_signed_by_ed25519",
//                "id_rsa_2048_pem_signed_by_rsa",
//                "id_rsa_2048_rfc4716_signed_by_ecdsa",
//                "id_rsa_2048_rfc4716_signed_by_ed25519",
                "id_rsa_2048_rfc4716_signed_by_rsa",
        ]
    }
}