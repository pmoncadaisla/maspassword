plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.maspassword.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.maspassword.app"
        // 26 is the floor for BOTH android.service.autofill.AutofillService
        // and java.util.Base64 (used throughout :core).
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.3.0"
    }

    buildTypes {
        release {
            // Kept unobfuscated on purpose: this app is security-sensitive and
            // ships as source; reviewability beats a few hundred KB.
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // All crypto / parsing / matching logic lives in :core (pure JVM, unit-tested).
    implementation(project(":core"))

    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.recyclerview:recyclerview:1.3.2")

    // Android Keystore-backed storage for the device token (never the keys).
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // BiometricPrompt gate (biometric or device credential).
    implementation("androidx.biometric:biometric:1.1.0")

    // QR scanning: zxing-android-embedded (JourneyApps). Chosen over ML Kit
    // because it has no Google Play Services dependency, is ~1 MB, fully
    // open source, and QR pairing is a one-shot flow where scan latency
    // does not matter. org.json is provided by the Android platform.
    implementation("com.journeyapps:zxing-android-embedded:4.3.0")
}
