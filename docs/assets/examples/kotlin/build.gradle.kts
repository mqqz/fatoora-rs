plugins {
    kotlin("jvm") version "2.1.20"
    application
}
repositories { mavenCentral() }
dependencies {
    implementation("com.fatoority:fatoority:0.4.4")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.8.1")
}
application { mainClass.set("MainKt") }
