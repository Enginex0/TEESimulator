import com.android.build.api.artifact.SingleArtifact
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import org.gradle.process.ExecOperations
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ktfmt)
}

ktfmt { kotlinLangStyle() }

// Helper class to get access to the ExecOperations service
abstract class GitExecutor @Inject constructor(private val execOperations: ExecOperations) {
    fun execute(command: String, currentWorkingDir: File): String {
        val byteOut = ByteArrayOutputStream()
        execOperations.exec {
            workingDir = currentWorkingDir
            commandLine = command.split("\\s".toRegex())
            standardOutput = byteOut
        }
        return String(byteOut.toByteArray()).trim()
    }
}

// Instantiate the helper class using Gradle's object factory
val gitExecutor = objects.newInstance(GitExecutor::class.java)

// versionCode = git commit count + floor offset. The 2026-07-08 public-release
// history scrub (0f1143a) rewrote history and dropped the raw commit count below
// the build number already shipped to testers (298), so post-scrub counts read as
// downgrades. The floor offset lifts versionCode back above that peak and keeps it
// monotonic across the rewrite; each later commit still bumps it by one.
val versionCodeFloorOffset = 5
val gitCommitCount =
    gitExecutor.execute("git rev-list HEAD --count", rootDir).toInt() + versionCodeFloorOffset
val gitCommitHash = gitExecutor.execute("git rev-parse --verify --short HEAD", rootDir)
val verName = "v6.0.1"

android {
    namespace = "org.matrix.TEESimulator"
    compileSdk = 36
    ndkVersion = "27.3.13750724"
    buildToolsVersion = "36.0.0"

    defaultConfig {
        applicationId = "org.matrix.TEESimulator"
        minSdk = 29
        targetSdk = 36
        versionCode = gitCommitCount
        versionName = verName
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            proguardFiles("proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }
    buildFeatures { buildConfig = true }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            buildStagingDirectory = layout.buildDirectory.get().asFile
        }
    }
}

kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_21) } }

dependencies {
    compileOnly(project(":stub"))
    compileOnly(libs.annotation)
    implementation(libs.bcpkix)
}

// --- Rust native cert gen build task ---
val buildRustCertgen by
    tasks.registering(Exec::class) {
        group = "TEESimulator-RS Native Build"
        description = "Builds libcertgen.so via cargo-ndk for arm64-v8a."

        workingDir = rootProject.projectDir.resolve("native-certgen")

        commandLine(
            "cargo",
            "ndk",
            "-t",
            "arm64-v8a",
            "-o",
            rootProject.projectDir.resolve("app/src/main/jniLibs").absolutePath,
            "build",
            "--release",
        )

        inputs.dir(rootProject.projectDir.resolve("native-certgen/src"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.toml"))
        inputs.file(rootProject.projectDir.resolve("native-certgen/Cargo.lock"))
        outputs.dir(rootProject.projectDir.resolve("app/src/main/jniLibs"))

        environment("ANDROID_NDK_HOME", android.ndkDirectory.absolutePath)
        environment(
            "PATH",
            "${System.getProperty("user.home")}/.cargo/bin:${System.getenv("PATH") ?: ""}",
        )
    }

// AGP auto-detects jniLibs/ as an input to mergeJniLibFolders — wire the dependency
tasks.configureEach {
    if (name.endsWith("JniLibFolders") && name.startsWith("merge")) {
        dependsOn(buildRustCertgen)
    }
}

// Auto-rewrite module/update.json on every packaging build so versionCode and
// zipUrl track gitCommitCount automatically, matching module.prop.
val refreshUpdateJson by
    tasks.registering {
        group = "TEESimulator-RS Module Packaging"
        description = "Rewrite module/update.json to match current verName and gitCommitCount."

        val updateJsonFile = rootProject.projectDir.resolve("module/update.json")
        val capturedVerName = verName
        val capturedCount = gitCommitCount

        inputs.property("verName", capturedVerName)
        inputs.property("gitCommitCount", capturedCount)
        outputs.file(updateJsonFile)

        doLast {
            val fullVer = "$capturedVerName-$capturedCount"
            updateJsonFile.writeText(
                """{
  "version": "$fullVer",
  "versionCode": $capturedCount,
  "zipUrl": "https://github.com/Enginex0/TEESimulator-RS/releases/download/$fullVer/TEESimulator-RS-$fullVer-Release.zip",
  "changelog": "https://raw.githubusercontent.com/Enginex0/TEESimulator-RS/main/module/changelog.md"
}
"""
            )
        }
    }

androidComponents {
    onVariants(selector().all()) { variant ->
        val capitalized = variant.name.replaceFirstChar { it.uppercase() }
        val isDebug = variant.buildType == "debug"

        // --- Define output locations and file names ---
        // Stage all files in a temporary directory inside 'build' before zipping
        val tempModuleDir = project.layout.buildDirectory.dir("module/${variant.name}")
        val zipFileName = "TEESimulator-RS-$verName-$gitCommitCount-$capitalized.zip"

        // Task 1: Prepare all module files in the temporary build directory.
        // Using Sync ensures that stale files from previous runs are removed.
        val prepareModuleFilesTask =
            tasks.register<Sync>("prepareModuleFiles${capitalized}") {
                group = "TEESimulator-RS Module Packaging"
                description = "Prepares all files for the ${variant.name} module zip."

                if (isDebug) {
                    dependsOn("package${capitalized}")
                } else {
                    dependsOn("minify${capitalized}WithR8")
                    dependsOn("strip${capitalized}DebugSymbols")
                }
                dependsOn(buildRustCertgen)
                dependsOn(refreshUpdateJson)

                if (isDebug) {
                    from(variant.artifacts.get(SingleArtifact.APK)) {
                        include("*.apk")
                        rename { "service.apk" }
                    }
                } else {
                    from(
                        project.layout.buildDirectory.dir(
                            "intermediates/dex/${variant.name}/minify${capitalized}WithR8"
                        )
                    ) {
                        include("classes.dex")
                    }
                }

                val nativeLibsDir =
                    if (isDebug) {
                        "intermediates/merged_native_libs/${variant.name}/merge${capitalized}NativeLibs/out/lib"
                    } else {
                        "intermediates/stripped_native_libs/${variant.name}/strip${capitalized}DebugSymbols/out/lib"
                    }
                from(project.layout.buildDirectory.dir(nativeLibsDir)) {
                    into("lib")
                    include(
                        "**/libinject.so",
                        "**/libTEESimulator.so",
                        "**/libsupervisor.so",
                        "**/libcertgen.so",
                    )
                }

                // Now, copy and process the files from 'module' directory.
                val sourceModuleDir = rootProject.projectDir.resolve("module")
                from(sourceModuleDir) {
                    exclude("module.prop") // Exclude the template file.
                    exclude("diag.sh") // Debug-only diagnostic plane; included for debug below.
                }

                // Copy and filter the module.prop template separately.
                from(sourceModuleDir) {
                    include("module.prop")
                    // Use expand() for simple key-value replacement.
                    expand(
                        "REPLACEMEVERCODE" to gitCommitCount.toString(),
                        "REPLACEMEVER" to "$verName-$gitCommitCount",
                    )
                }

                if (isDebug) {
                    from(sourceModuleDir) { include("diag.sh") }
                }

                // The destination for all the above 'from' operations.
                into(tempModuleDir)

                if (isDebug) {
                    doLast {
                        // Debug-only: grant the keystore + soterserver (platform_app) domains
                        // external-storage access for the per-UID NDJSON sink. diag.sh (shipped
                        // only in debug) carries the shell side of the diagnostic plane.
                        tempModuleDir.get().asFile.resolve("sepolicy.rule")
                            .appendText(
                                "\nallow keystore media_rw_data_file { dir file } *" +
                                    "\nallow platform_app media_rw_data_file { dir file } *\n",
                            )
                    }
                }
            }

        // Task 2: Zip the prepared files from the temporary directory.
        val zipTask =
            tasks.register<Zip>("zip${capitalized}") {
                group = "TEESimulator-RS Module Packaging"
                description = "Creates the flashable zip for the ${variant.name} module."
                dependsOn(prepareModuleFilesTask)

                archiveFileName.set(zipFileName)
                destinationDirectory.set(project.rootDir.resolve("out"))
                from(tempModuleDir) // Zip the entire contents of the staging directory.
            }

        // Task 3: A helper function to create installation tasks for different root providers.
        fun createInstallTasks(rootProvider: String, installCli: String) {
            val pushTask =
                tasks.register<Exec>("push${rootProvider}Module${capitalized}") {
                    group = "TEESimulator-RS Module Installation"
                    description =
                        "Pushes the ${variant.name} module to the device for $rootProvider."
                    dependsOn(zipTask)
                    commandLine(
                        "adb",
                        "push",
                        zipTask.get().archiveFile.get().asFile,
                        "/data/local/tmp",
                    )
                }

            val installTask =
                tasks.register<Exec>("install${rootProvider}${capitalized}") {
                    group = "TEESimulator-RS Module Installation"
                    description = "Installs the ${variant.name} module via $rootProvider."
                    dependsOn(pushTask)
                    commandLine(
                        "adb",
                        "shell",
                        "su",
                        "-c",
                        "$installCli /data/local/tmp/$zipFileName",
                    )
                }

            tasks.register<Exec>("install${rootProvider}AndReboot${capitalized}") {
                group = "TEESimulator-RS Module Installation"
                description = "Installs the ${variant.name} module via $rootProvider and reboots."
                dependsOn(installTask)
                commandLine("adb", "reboot")
            }
        }

        createInstallTasks("Magisk", "magisk --install-module")
        createInstallTasks("Ksu", "ksud module install")
        createInstallTasks("Apatch", "/data/adb/apd module install")
    }
}
