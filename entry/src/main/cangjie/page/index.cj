package ohos_app_cangjie_entry.page
import kit.ArkUI.*
import ohos.arkui.state_macro_manage.Entry
import ohos.arkui.state_macro_manage.Component
import ohos.arkui.state_macro_manage.State
import ohos_app_cangjie_eudi_cjx509.runX509Demo



@Entry
@Component
public class EntryView {
    @State
    var resultText: String = "x509 module scaffold"

    func build() {
        Column {
            Button("Run X509 Demo")
                .onClick({
                    evt => this.resultText = runX509Demo()
                })
                .fontSize(18)
                .width(80.percent)
                .height(50.vp)
                .margin(top: 40.vp)
            Text(this.resultText)
                .fontSize(14)
                .width(90.percent)
                .margin(top: 24.vp)
        }
        .width(100.percent)
        .height(100.percent)
        .justifyContent(FlexAlign.Start)
        .padding(top: 80.vp)
    }
}
