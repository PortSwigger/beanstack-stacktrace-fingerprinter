plugins {
    id("java")
}

group "io.beanstack"
version "0.7.0"

repositories {
    mavenCentral()
}

dependencies {
    compileOnly("net.portswigger.burp.extender:burp-extender-api:2.3")
    compileOnly("com.cedarsoftware:json-io:4.14.1")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.19.2")
}

tasks.withType<JavaCompile> {
    sourceCompatibility = "21"
    targetCompatibility = "21"
    options.encoding = "UTF-8"
    options.compilerArgs.add("-Xlint:deprecation")
    options.compilerArgs.add("-Xlint:unchecked")
}

tasks.jar {
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations.runtimeClasspath.get().filter { it.isDirectory })
    from(configurations.runtimeClasspath.get().filterNot { it.isDirectory }.map { zipTree(it) })
}

