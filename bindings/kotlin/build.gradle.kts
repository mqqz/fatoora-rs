import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    kotlin("jvm") version "2.1.20"
    kotlin("android") version "2.1.20" apply false
    id("com.android.library") version "8.9.2" apply false
    id("com.android.application") version "8.9.2" apply false
    `java-library`
    id("org.jetbrains.dokka") version "2.2.0"
    `maven-publish`
}
group = "com.fatoority"
version = "0.4.2"

kotlin {
    compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8); freeCompilerArgs.add("-opt-in=kotlin.ExperimentalUnsignedTypes") }
    sourceSets.main { kotlin.srcDirs("generated/raw", "generated/facade") }
    sourceSets.test { kotlin.srcDir("examples") }
}
java { sourceCompatibility = JavaVersion.VERSION_1_8; targetCompatibility = JavaVersion.VERSION_1_8; withSourcesJar() }
dependencies {
    implementation("net.java.dev.jna:jna:5.18.1")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    testImplementation(kotlin("test-junit"))
    testImplementation("junit:junit:4.13.2")
}
tasks.test {
    if (providers.gradleProperty("testJava").isPresent) {
        javaLauncher.set(javaToolchains.launcherFor { languageVersion.set(JavaLanguageVersion.of(providers.gradleProperty("testJava").get().toInt())) })
    }
    systemProperty("jna.library.path", providers.gradleProperty("nativeDir").orElse(rootDir.resolve("../../target/release").absolutePath).get())
    systemProperty("fatoora.fixtures", rootDir.resolve("../../fatoora-core/tests/fixtures/sdk-parity").absolutePath)
}
sourceSets.test { java.srcDir("examples") }
sourceSets.main { resources.srcDir(layout.buildDirectory.dir("nativeResources")) }
tasks.jar {
    from(rootDir.resolve("README.md"))
    from(rootDir.resolve("../../THIRD_PARTY_NOTICES.md"))
    from(rootDir.resolve("../../LICENSE-MIT"))
    from(rootDir.resolve("../../LICENSE-APACHE"))
    from(rootDir.resolve("../../fatoora-core/tests/fixtures/business-rules")) {
        include("LICENSE-LGPL-3.0.txt", "LICENSE-GPL-3.0.txt", "NOTICE.md")
        into("licenses/zatca")
    }
}
dokka {
    dokkaSourceSets.configureEach {
        perPackageOption {
            matchingRegex.set("com\\.fatoora\\.raw.*")
            suppress.set(true)
        }
    }
}
val javadocJar by tasks.registering(Jar::class) {
    archiveClassifier.set("javadoc")
    from(tasks.dokkaGeneratePublicationHtml.flatMap { it.outputDirectory })
    from("README.md")
}
publishing { publications { create<MavenPublication>("jvm") {
    from(components["java"])
    artifactId = "fatoority"
    artifact(javadocJar)
} } }

publishing.repositories { maven { name = "staging"; url = uri(layout.buildDirectory.dir("repository")) } }

// The native code includes separately licensed ZATCA-derived rule data.
publishing.publications.withType<MavenPublication>().configureEach {
    pom {
        name.set("Fatoority")
        description.set("Kotlin and Java bindings for the Fatoority ZATCA SDK")
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
