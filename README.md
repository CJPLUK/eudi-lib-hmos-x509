# eudi_lib_x509

EU Digital Identity Wallet 的 **X.509 证书模块**(仓颉 / HarmonyOS)。把平台能力 `stdx.crypto.x509` 包成稳定门面,并补齐平台缺失的 **CRL(RFC 5280)解析 / 吊销检查**与**证书扩展工具**。

接口面由消费方 [eudi-lib-ios-iso18013-security](https://github.com/eu-digital-identity-wallet/eudi-lib-ios-iso18013-security)(© European Commission)的真实用法驱动——iOS 侧用 swift-certificates + swift-asn1,本模块用 `stdx.crypto.x509` + 自写 RFC 5280 层填补缺口。

## 功能

| 子包 | 能力 | 实现 |
|---|---|---|
| **core** | `Cert.fromDer/fromPem` 解析 + 字段(serial/issuer/subject/有效期/publicKey/keyUsage)、`verifyChain(leaf, intermediates, roots[, date])` 链验证、`getPublicKeyX963()` 提取未压缩 EC 公钥(0x04‖X‖Y)、`toDer()` | ~90% 委托 `stdx.crypto.x509` |
| **crl** | `Crl.fromDer/fromPem` 解析、`isRevoked(serial)` 吊销判定、`extensionValue(cert, oid)` 任意 OID 扩展提取、`hasDuplicateExtensions(cert)` | 自写 RFC 5280 DER(平台缺口),畸形输入抛 `CrlError` 不 panic |

## 仓库结构(团队统一 cbor 形态)

```
eudi_lib_x509/
├── eudi_cjx509/                   ← HAR 模块(交付单元,pkg ohos_app_cangjie_eudi_cjx509)
│   └── src/main/cangjie/x509/
│       ├── core/x509_facade.cj    ← Cert / verifyChain / getPublicKeyX963
│       └── crl/crl.cj             ← Crl / isRevoked / extensionValue
├── entry/                         ← 测试面板 HAP(39 个设备 E2E + "Run X509 Demo" 按钮)
│   └── libs/{stdx, arm64-v8a}/    ← stdx 1.1.3.1 + OpenSSL/libsecurec 运行时件(已带)
└── (无 third_party — 仅依赖 stdx,零跨库 cjpm 依赖)
```

## 下游消费(cjpm path 依赖)

```bash
git clone https://github.com/CJPLUK/eudi-lib-hmos-x509 third_party/eudi_lib_x509
cd third_party/eudi_lib_x509 && git checkout v0.1.0
```

```toml
[dependencies]
  [dependencies.ohos_app_cangjie_eudi_cjx509]
    path = "../third_party/eudi_lib_x509/eudi_cjx509"
```

```cangjie
import ohos_app_cangjie_eudi_cjx509.x509.core.*
import ohos_app_cangjie_eudi_cjx509.x509.crl.*
```

本模块仅依赖 `stdx`(无跨库 cjpm 依赖),消费方无需额外 clone 上游库。但 `stdx.crypto.x509` 在设备上运行时 `dlopen` OpenSSL,需保证 HAP 带上 `entry/libs/arm64-v8a/` 三件套(本仓已带,详见团队 lib-packaging-spec §7)。

## 构建

要求:DevEco Studio(含 OpenHarmony SDK)+ Cangjie SDK(cjc 1.1.3+)。环境变量与命令同团队 lib-packaging-spec,参照 [eudi_lib_sdjwt](https://github.com/CJPLUK/eudi-lib-hmos-sdjwt) README 的"构建"一节(完全相同)。

```bash
cd eudi_cjx509 && cjpm build --target aarch64-linux-ohos   # HAR 模块
cd ../entry    && cjpm build --target aarch64-linux-ohos   # 测试面板
```

测试面板:app 内点 **Run X509 Demo** → `OK: cert=Test Leaf, chain=PASS, revoked_hit=true, clean_miss=false`(解析→链验证→吊销判定全链)。

## 测试与验证

- **39 个设备端 E2E 用例**(`entry/src/main/cangjie/unittest_engine.cj`,OpenHarmonyTestRunner):
  - core 14:字段解析 / DER 往返 / 链验证(正例 + 错根 + 过期负例)/ x963 已知向量比对(`stdx.crypto.x509` native dlopen 链真机实证)
  - crl 20:全字段解析 / isRevoked 命中-未命中-大小写 / **畸形 DER 抛 CrlError 不 panic**(截断 / 空 / 错 PEM 标签)/ 扩展提取 / 重复扩展检测
  - demo 4 + UI 冒烟 1
- **多个 host 单测**(`eudi_cjx509/src/test/cangjie/`),测试向量由 openssl 现场生成(测试 CA 链 + CRL)

## License

[Apache License 2.0](LICENSE)。接口面源自 eudi-lib-ios-iso18013-security(© European Commission)的衍生消费;归属与捆绑件声明见 [NOTICE](NOTICE)。
