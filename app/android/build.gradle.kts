allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

val newBuildDir: Directory =
    rootProject.layout.buildDirectory
        .dir("../../build")
        .get()
rootProject.layout.buildDirectory.value(newBuildDir)

subprojects {
    val newSubprojectBuildDir: Directory = newBuildDir.dir(project.name)
    project.layout.buildDirectory.value(newSubprojectBuildDir)
}
subprojects {
    project.evaluationDependsOn(":app")
}

// 部分 Flutter 插件（如 desktop_drop）仍按 android-33 编译，而它们的 AndroidX 传递依赖要求 34 以上，
// 直接构建会在 checkAarMetadata 阶段失败（15 条 AAR metadata 错误）。
// 这里把所有插件的 compileSdk 统一提升到 36，避免逐个 fork 插件；
// 用反射是为了不在根脚本里硬依赖 AGP 类型，保持脚本可移植。
subprojects {
    plugins.withId("com.android.library") {
        val androidExt = extensions.findByName("android")
        if (androidExt != null) {
            runCatching {
                androidExt.javaClass
                    .getMethod("compileSdkVersion", Int::class.javaPrimitiveType)
                    .invoke(androidExt, 36)
            }.onFailure {
                logger.warn("提升 ${project.name} 的 compileSdk 失败：${it.message}")
            }
        }
    }
}

tasks.register<Delete>("clean") {
    delete(rootProject.layout.buildDirectory)
}
