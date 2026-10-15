import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.library")
    kotlin("android")
    `maven-publish`
}
group = rootProject.group
version = rootProject.version
android {
    namespace = "com.fatoora"
    compileSdk = 35
    ndkVersion = "28.2.13676358"
    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    sourceSets["main"].apply {
        java.srcDirs("../src/main/kotlin", "../generated/raw", "../generated/facade")
        jniLibs.srcDir("build/native")
        resources.srcDir("build/notices")
    }
    sourceSets["androidTest"].assets.srcDir("../../../fatoora-core/tests/fixtures/sdk-parity")
    compileOptions { sourceCompatibility = JavaVersion.VERSION_1_8; targetCompatibility = JavaVersion.VERSION_1_8 }
    // Rust already strips the library; preserve exactly the verified staged bytes.
    packaging.jniLibs.keepDebugSymbols += "**/libfatoora_ffi.so"
    publishing { singleVariant("release") { withSourcesJar() } }
}
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8); freeCompilerArgs.add("-opt-in=kotlin.ExperimentalUnsignedTypes") } }
dependencies {
    implementation("net.java.dev.jna:jna:5.18.1@aar")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    androidTestImplementation("androidx.test:runner:1.6.2")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
}
val notices by tasks.registering(Copy::class) {
    into(layout.buildDirectory.dir("notices"))
    from(rootDir.resolve("README.md"))
    from(rootDir.resolve("licenses")) { into("licenses") }
    from(rootDir.resolve("../../THIRD_PARTY_NOTICES.md"))
    from(rootDir.resolve("../../LICENSE-MIT"))
    from(rootDir.resolve("../../LICENSE-APACHE"))
    from(rootDir.resolve("../../fatoora-core/tests/fixtures/business-rules")) {
        include("LICENSE-LGPL-3.0.txt", "LICENSE-GPL-3.0.txt", "NOTICE.md")
        into("licenses/zatca")
    }
}
tasks.named("preBuild") { dependsOn(notices) }
afterEvaluate {
    publishing { publications { create<MavenPublication>("android") {
        from(components["release"])
        artifactId = "fatoority-android"
        // Desktop and Android expose the same Kotlin/Java source API.
        artifact(rootProject.tasks.named("javadocJar"))
    } } }
}

publishing.repositories { maven { name = "staging"; url = uri(rootProject.layout.buildDirectory.dir("repository")) } }

publishing.publications.withType<MavenPublication>().configureEach {
    pom {
        name.set("Fatoority Android")
        description.set("Kotlin and Java bindings for Android with bundled native libraries")
        url.set("https://github.com/mqqz/fatoority")
        developers { developer {
            id.set("mqqz")
            name.set("mqqz")
            url.set("https://github.com/mqqz")
        } }
        scm {
            url.set("https://github.com/mqqz/fatoority")
            connection.set("scm:git:https://github.com/mqqz/fatoority.git")
            developerConnection.set("scm:git:ssh://git@github.com/mqqz/fatoority.git")
        }
        licenses { license {
            name.set("See THIRD_PARTY_NOTICES.md")
            url.set("https://github.com/mqqz/fatoority/blob/main/THIRD_PARTY_NOTICES.md")
        } }
    }
}

tasks.withType<JavaCompile>().configureEach { options.encoding = "UTF-8" }
