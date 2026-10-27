/**
 * x509_demo_test.cj — unit tests for runX509Demo() in the eudi_cjx509 root package.
 *
 * Only calls runX509Demo() via the public API; does not import internal packages directly.
 */
package ohos_app_cangjie_eudi_cjx509_local_test

import ohos_app_cangjie_eudi_cjx509.runX509Demo
import std.unittest.*
import std.unittest.testmacro.*

@Test
class X509DemoFunctionUT {
    @TestCase
    func testRunX509DemoReturnsOk() {
        let result = runX509Demo()
        @Expect(result.startsWith("OK:"), true)
    }

    @TestCase
    func testRunX509DemoContainsChainPass() {
        let result = runX509Demo()
        @Expect(result.contains("chain=PASS"), true)
    }

    @TestCase
    func testRunX509DemoContainsRevokedHitTrue() {
        let result = runX509Demo()
        @Expect(result.contains("revoked_hit=true"), true)
    }

    @TestCase
    func testRunX509DemoContainsCleanMissFalse() {
        let result = runX509Demo()
        @Expect(result.contains("clean_miss=false"), true)
    }
}
