plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

android {
    namespace = "com.zhiwei.security"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.zhiwei.security"
        minSdk = 26
        targetSdk = 35
    versionCode = 17
    versionName = "1.6.2"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    signingConfigs {
        // 正式版签名密钥（知微安全自有）
        create("release") {
            storeFile = file("keystore/release.keystore")
            storePassword = "zhiwei2026"
            keyAlias = "zhiwei"
            keyPassword = "zhiwei2026"
        }
        // AOSP 公开 platform testkey（仅对 userdebug/testkey 签名的系统有效）
        create("platform") {
            storeFile = file("keystore/platform.keystore")
            storePassword = "android"
            keyAlias = "platform"
            keyPassword = "android"
        }
    }

    flavorDimensions += "privilege"
    productFlavors {
        // 普通版：可安装在任何设备
        create("normal") {
            dimension = "privilege"
            versionNameSuffix = ""
            signingConfig = signingConfigs.getByName("release")
        }
        // 系统版：sharedUserId=android.uid.system + platform testkey 签名
        // 只能在 testkey 签名的系统（userdebug/模拟器/部分工程机）上安装
        create("system") {
            dimension = "privilege"
            versionNameSuffix = "-system"
            signingConfig = signingConfigs.getByName("platform")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    buildFeatures {
        compose = true
        aidl = true
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
        jniLibs {
useLegacyPackaging = true // adb 二进制需真实解压到 nativeLibraryDir
        }
    }
}

// Force use of ARM64 binaries for AAPT2 in Proot environment
configurations.all {
    resolutionStrategy.eachDependency {
        if (requested.group == "com.android.tools.build" && requested.name == "aapt2") {
            useTarget("com.android.tools.build:aapt2:${'$'}{requested.version}:linux-aarch64")
        }
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)

    // Shizuku
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")

    // Material Icons Extended
    implementation("androidx.compose.material:material-icons-extended:1.7.6")

    // Navigation Compose
    implementation("androidx.navigation:navigation-compose:2.8.5")

    // DataStore
    implementation("androidx.datastore:datastore-preferences:1.1.1")

    // Kotlinx Coroutines
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")

    // Coil for icons
    implementation("io.coil-kt:coil-compose:2.7.0")

    // Accompanist System UI Controller
    implementation("com.google.accompanist:accompanist-systemuicontroller:0.36.0")

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}
