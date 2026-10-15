plugins { id("com.android.application") }
android {
    namespace = "com.fatoora.consumer"
    compileSdk = 35
    defaultConfig {
        applicationId = "com.fatoora.consumer"
        minSdk = 26
        targetSdk = 35
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    buildTypes["debug"].matchingFallbacks += listOf("release")
    sourceSets["androidTest"].apply {
        java.srcDir("../android/src/androidTest/java")
        assets.srcDir("../../../fatoora-core/tests/fixtures/sdk-parity")
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_1_8; targetCompatibility = JavaVersion.VERSION_1_8 }
}
dependencies {
    // Resolve the built AAR and transitive metadata; no project dependency.
    implementation("com.fatoority:fatoority-android:${rootProject.version}")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}

tasks.withType<JavaCompile>().configureEach { options.encoding = "UTF-8" }
