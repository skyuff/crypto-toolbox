$mvnOut = java -classpath ".mvn\wrapper\maven-wrapper.jar" "-Dmaven.multiModuleProjectDirectory=." org.apache.maven.wrapper.MavenWrapperMain dependency:build-classpath --define mdep.outputFile=- -q 2>$null
$cp = ($mvnOut | Select-Object -Last 1).Trim()
$fullCp = "target\classes;target\test-classes;$cp"
Write-Host "classpath length: $($fullCp.Length)"
java -cp "$fullCp" com.smtool.module.timestamp.TimestampDemoTest
