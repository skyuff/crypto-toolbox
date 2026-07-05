# 商用密码检测工具箱 - 后端启动脚本 (PowerShell)
# 用法:
#   .\run.ps1              首次或代码变更后: 打包并以 jar 方式启动 (推荐, 端口 8080)
#   .\run.ps1 jar          直接以已构建的 jar 启动 (不重新打包)
#   .\run.ps1 <maven参数>  透传给 maven, 例如: .\run.ps1 clean package

$ErrorActionPreference = "Stop"
$base = (Get-Location).Path + "\"
$wrapperJar = ".mvn\wrapper\maven-wrapper.jar"
$appJar = "target\crypto-toolbox-backend.jar"

function Invoke-Mvn {
    param([string[]]$mvnArgs)
    java "-Dmaven.multiModuleProjectDirectory=$base" -classpath $wrapperJar `
        org.apache.maven.wrapper.MavenWrapperMain @mvnArgs
}

if ($args.Count -eq 1 -and $args[0] -eq "jar") {
    # 直接运行已构建的 jar
    java -jar $appJar
}
elseif ($args.Count -eq 0) {
    # 默认: 打包为 fat jar 再运行 (中文路径下比 spring-boot:run 更稳定)
    Invoke-Mvn @("-DskipTests", "package")
    java -jar $appJar
}
else {
    # 透传给 maven
    Invoke-Mvn $args
}
