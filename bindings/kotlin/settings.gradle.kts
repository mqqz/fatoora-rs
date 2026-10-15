pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement {
    repositories {
        exclusiveContent {
            forRepository { maven { url = uri("build/repository") } }
            filter { includeGroup("com.fatoority") }
        }
        google()
        mavenCentral()
    }
}
rootProject.name = "fatoority"
// Desktop builds need no Android SDK.
if (providers.gradleProperty("android").orNull == "true") include(":android", ":android-consumer")
