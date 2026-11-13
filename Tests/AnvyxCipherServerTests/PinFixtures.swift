import Foundation
import Security

/// Self-signed throwaway certificates (CN=pin-test.example) with the pin that
/// this pipeline printed for each:
///
///     openssl x509 -in cert.pem -pubkey -noout | openssl pkey -pubin -outform der \
///       | openssl dgst -sha256 -binary | base64
struct PinFixture {
    let name: String
    let certificateBase64: String
    let pin: String

    var certificate: SecCertificate? {
        Data(base64Encoded: certificateBase64).flatMap { SecCertificateCreateWithData(nil, $0 as CFData) }
    }

    static let rsa2048 = PinFixture(
        name: "rsa2048",
        certificateBase64: "MIICtDCCAZwCCQD1+j18um914jANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBwaW4tdGVzdC5leGFtcGxlMCAXDTI2MTExMzA5MTQzOFoYDzIxMjYxMDIwMDkxNDM4WjAbMRkwFwYDVQQDDBBwaW4tdGVzdC5leGFtcGxlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmDxu+lJIQJzN5CNL/SxTkA0cl2McGN/2cWkZGE8d6bw/sbzfrbkPJWaZc/hTZjksh4R+/A2BJ+RbbpBG+fhp2YpHm/zgK5GYq9t3TaLrDWYzrMnzU77tXt69bbUeuYumQr7NF42xTmsrIL1FiUWBcAjM60v8qWlwJVE5mlHezE0iuNhq4nlYW+wKm2Y3lfdo9t3RYPqcL301JONTeO+8eHXSjcLofnuwQ/b4Cucmr8nW8MGlInpYw0JiCKyn/z9FeTMvZxoPoTaTTvY5O3EFxj7hf8H3da+DIZI4awIMcNKqvQiMiLqX8qrcp4OjxmidtJhxKlR0KSKOrDsfZc4c9wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQB90Bn8Q9qIlDG2njSB5Xo0YG6Zht0RJc7eTemf9jiSdA8KSW0NITlXybi1SCL/2TqfOsSfM4cUJAJILqJszjFBxCeFz34XuCgg68KwnuRMy/UfilDu7+w0qPnUMvrqKBHyH4eiGDMXLEmJMYHWKQ5ePawCDf/zrkKoYLBsqfaLGDauNr42ijte1b4/7GVcKwtD9Kz/wN+nOJNmpiGELoxGAC09uBC/ZvBGI73Wfs2dati+VeAGWxqhp1a+4kUVX52XtyeX8B33h+JsReTt5sb98zNHoVTc0cFxWfTYo7RA4ND/TIDJnprPGBsZPkZTw2X6HlaR+Xnj1HCKzSb311rR",
        pin: "r8YVeoVgyf/++riYcLCo8WH/Kv3v5J8vOzEHdGXHdXE=")

    static let rsa3072 = PinFixture(
        name: "rsa3072",
        certificateBase64: "MIIDtDCCAhwCCQClzRpp0I7VdTANBgkqhkiG9w0BAQsFADAbMRkwFwYDVQQDDBBwaW4tdGVzdC5leGFtcGxlMCAXDTI2MTExMzA5MTQzOFoYDzIxMjYxMDIwMDkxNDM4WjAbMRkwFwYDVQQDDBBwaW4tdGVzdC5leGFtcGxlMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA8LFRcOLs4n3vTiOOw+S32SfsrRkBb7Iqg57dzndHt35m08kbM7LSHUAe8lb3XRp/G3YJdWZrDXt57jE2dq0uGt1wcNrWryPowO7ymZWKOMVn2Fdaz7ar7oSz4t5M3g7rGsj7yJgg+chC7dXUFJ/N9n8gS4PHyia/AZ9OBtZnDJX1DSOhIMSQqDUenwnh9HX8GhA4zclLt9r4VObbZPNi00V7BkyvbcLWxD+28+UZTCcy+nLOz+5IAmskSmyhgEIv9tzdu2w1daX1wUfUeSYNTrUbXB2h7yZwUSZeiBoxXs9TxYfhDhmGWPQZW3aQYOZixuZfWiEqaELV29wuSbfv+ZJeSqBerF57N3bGIyQlb+Jn0B1bypUmdzdXT+jSObfbwb7GJQrd5DPBiDl0KiX5qJbVcAujrgEUgm1EKaDo/z5mtBNjBwVLFWJYGWd9MVuBo1TYHol8tzI7xJU9EVNfxKYIOanZ617vUuB45KXaKGZg3QCrrArgch+xy6sltksBAgMBAAEwDQYJKoZIhvcNAQELBQADggGBAKcveoshrMeLHGjoX9vjvJIzejbrelUkb8lw2bAo1zAJvrBn6+YRVCHScwkQEYSMb/humao+9Wqy5C5+ryOleq+Gj6KpX/0EgAd1rKsgfc2twx5IT8feqxO2kk5R/u9xUUX1+6xYoYdQsWv6JJ2Kw/preIX1ro1s7fvnBQB7QTHYPBmePsYlKxDOg3Y91c9SLaL7Bxq01I6REl68GtGpRsRx4l1rC7BiErtFl0ULYI8aZvCYYGqmYgFAjOftoLW/vc5SHkYakx/n1JjeZddPYh4iRn17ToA5kxxjNwgnVg0YQD48MLNJT3ANeYf2kcO1Mdcgq9I2J80q3DsrGQQMGMC6z0sHsFwpNtabqcmWHGkzKpZpjqFIczlWO35NCz6lBhetY+6zEqDel7J43xzU8u8OdtnQO34YmslDS2HkCYIbRIeakK7zcDuX4R+dAi6UDOCbKinVu22uRRODR/PvjYx1AVbDv0UhBiHMIi2hCCbP+TykT3dWVY0wWLF3VR2z5Q==",
        pin: "D8ixOsfeWi+QDrw+Hph1l2f0TLg2LW5b31lbFb6s4CY=")

    static let p256 = PinFixture(
        name: "p256",
        certificateBase64: "MIIBJjCBzgIJAOJq0LJykUHqMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEHBpbi10ZXN0LmV4YW1wbGUwIBcNMjYxMTEzMDkyMjMzWhgPMjEyNjEwMjAwOTIyMzNaMBsxGTAXBgNVBAMMEHBpbi10ZXN0LmV4YW1wbGUwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATzmU1siZPl4NXfd/a5YBL5fPlKsQlbajQv2Z1P0yQoGa9YSXHIERNvCXn6c2VdzAz7DIsWO8kE3rCzRU5QHIOVMAoGCCqGSM49BAMCA0cAMEQCIB91TB/m80FmdXcudGpCNSULvdpP6ZNUiZNH3KGlPwi7AiAoHI6DWDmUcx6/luEM/mwhz5PMEepZesMBa0OMcKy0kg==",
        pin: "p8wpsTxg26c0K+Fvf8a3HPQtr/l6Bn3FUetLQX17vao=")

    static let p384 = PinFixture(
        name: "p384",
        certificateBase64: "MIIBZDCB6wIJALMNnpVzKNQBMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEHBpbi10ZXN0LmV4YW1wbGUwIBcNMjYxMTEzMDkyMjMzWhgPMjEyNjEwMjAwOTIyMzNaMBsxGTAXBgNVBAMMEHBpbi10ZXN0LmV4YW1wbGUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASA9oX7RUa+vZtzH3sT65G//vVbk7AZqHYOeLvLPNlJRlSlnay8xpfOftCwmnLefIlthPiA+g9CFLHqVTr9IiOH/CBRoU65YrnD2zwbOcL1itTTnceYQEwc4j0k4MBG96UwCgYIKoZIzj0EAwIDaAAwZQIwH2KISu4B4CMJuZY+RIiBGxuIM9Jolqg+INl9vtThvAPdsqvFmD4GTwsgMwRIWQAfAjEAupBDLlta1SnkJwTZ0MkMZMfEjy29yTKSEGS+J4mNl0r8edNEEmhnh6Nx3P/+B8TG",
        pin: "eugIkI7lHF1HrIL9s6OhJvqq98Or0RhvIc4CRUB/R0k=")

    static let p521 = PinFixture(
        name: "p521",
        certificateBase64: "MIIBsDCCARECCQDrb0ME0acENDAKBggqhkjOPQQDAjAbMRkwFwYDVQQDDBBwaW4tdGVzdC5leGFtcGxlMCAXDTI2MTExMzA5MjIzM1oYDzIxMjYxMDIwMDkyMjMzWjAbMRkwFwYDVQQDDBBwaW4tdGVzdC5leGFtcGxlMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA29uW7UON1t/u+tumfMJwlEkx1hxMH2BsyWvAaze1+M1bikWK8M7XFf1kuad/JnatsPuB7DdBY1DlQQJ3Ng1uSzwBkOlzsHnutSqf0iPoq5DUOVpKN/xr0XgFo0UJaHKUwnFZfLuYrzff3QMYrdImbev9EnzvrYK4Umwi3y4KvRqvUaUwCgYIKoZIzj0EAwIDgYwAMIGIAkIBvux4JNoIbK++yhbHnQJxLNNoC8C+76r6HuXzyTAzPL2Cgm81eSdT/Ik+c1F+EEFxnMhNspHwDpYO2IyeRarSGGgCQgCS93f3Ip6xk5uiq+ooMkl1jwL7NgoUtR/ZCXY7rSW0aGq0rj2et9cFBHyidWOgrBOkBlE1VECd+vyPw53HeT5YgQ==",
        pin: "W4BUiVJcOXumDaXzvglgple5wgqUy89tSfXCx8MZ5y0=")

    static let all = [rsa2048, rsa3072, p256, p384, p521]
}
