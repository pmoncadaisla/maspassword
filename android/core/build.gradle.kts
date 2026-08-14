// :core — pure-JVM Kotlin module. No Android dependencies, so all the
// security-critical logic (crypto, TOTP, QR payload, domain matching, JSON
// models) is unit-testable with plain JUnit: `./gradlew :core:test`.
plugins {
    id("org.jetbrains.kotlin.jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // org.json is provided by the Android platform at runtime. `compileOnly`
    // keeps it off the APK classpath (bundling it would clash with the
    // platform copy); tests get a real implementation from Maven Central.
    compileOnly("org.json:json:20240303")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}

tasks.test {
    useJUnit()
    testLogging {
        events("passed", "failed", "skipped")
    }
}
