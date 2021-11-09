# Android 运行机制以及打包机制简述

## dex 文件格式

不确定时查一查即可，或者没事的时候看看，巩固一下，和 ELF 文件格式很像，但是内容没有 ELF 多。

链接：https://ctf-wiki.org/android/basic_operating_mechanism/java_layer/dex/dex/

## Native 层 

动态加载 so 主要使用两种方法分别是 `System.loadLibrary` 和 `System.load` ，第一种方法会在项目的 libs 目录下寻找要加载的 so ，第二种方法会根据指定的绝对路径来加载 so 。

两种方法最后都会调用 Runtime 中的 doLoad 函数，doLoad 函数中会先确定要加载的 so 的路径，确定路径后转去调用 nativeLoad 函数。

nativeLoad 函数会调用 Dalvik_java_lang_Runtime_nativeLoad 函数（Native 层的函数，C++ 代码），nativdLoad 也还是会先做一些检查，检查之后会调用 dvmLoadNativeCode 函数。

dvmLoadNativeCode 函数首先会调用 findSharedLibEntry 函数来检测是否已经加载过了这个 so 如果没有的话则使用 dl_open 来打开这个共享库，打开之后会调用 `si->CallConstructors();` 函数来构造一些相关信息，并且在 so 中如果存在 `.init` 和 `.init_array` 的话会先调用其中的代码，在调用完 `.init` 和 `.init_array` 这两处的代码之后，会为当前的 so 创建一个 entry 并将其添加到对应的 list 中，添加完成后，根据 so 的符号表，找到 JNI_OnLoad 函数，调用 JNI_OnLoad 函数。

流程如下：

```
System.loadLibrary --
					|---> doLoad ---> nativeLoad ---> dvmLoadNativeCode ---> JNI_OnLoad
System.load ---------
```

这说明加载 .so 文件时，会按照执行如下顺序的函数（如果不存在的话，就会跳过）

- .init 函数
- .init_array 中的函数
- JNI_OnLoad 函数

## 打包流程

流程图如下：

![](img/2021-11-03-14-35-40.png)

1. 首先使用 aapt 对资源文件进行打包，生成 R.java 文件
2. 如果使用了 AIDL 则需使用 AIDL 解析工具解析 AIDL 接口文件生成相应的 Java 代码
3. 使用 javac 将源代码，资源文件编译成 class 文件
4. 使用 dex 将 class 文件和其他第三方的 class 文件以及库转换为 dex 文件
5. 使用 apkbuilder 将资源文件和 dex 文件打包成 apk
6. 对打包后的 apk 进行签名
7. 在发布正式版之前，我们需要将 apk 包中资源文件距离文件的起始偏移修改为 4 字节的整数倍数，这样，在之后运行 app 的时候，速度会比较快。

**apk 文件结构：**

apk 文件也是一种 zip 文件。因此，我们可以使用解压 zip 的工具来对其进行解压。一个典型的 apk 文件的结构如下图所示。其中，关于每一部分的介绍如下

![](img/2021-11-03-14-41-07.png)

- AndroidManifest.xml
  - 该文件主要用于声明应用程序的名称，组件，权限等基本信息。
- class.dex
  - 该文件是 dalvik 虚拟机对应的可执行文件，包含应用程序的可执行代码。
- resource.arsc
  - 该文件主要是应用程序编译后的二进制资源以及资源位置与资源 id 之间的映射关系，如字符串。
- assets
  - 该文件夹一般用于包含应用程序的原始资源文件，例如字体和音乐文件。程序在运行的时候，可以通过 API 获取这些信息。
- lib/
  - lib 目录下主要用于存储通过 JNI（Java Native Interface）机制使用的本地库文件，并且会按照其支持的架构，分别创建对应的子目录。
- res/
  - 该目录主要包含了 Android 应用引用的资源，并且会按照资源类型进行存储，如图片，动画，菜单等。主要还有一个 value 文件夹，包含了各类属性资源
- colors.xml→颜色资源
- dimens.xml---> 尺寸资源
- strings---> 字符串资源
- styles.xml→样式资源
- META-INF/
  - 类似于 JAR 文件，APK 文件中也包含了 META-INF 目录，用于存放代码签名等文件，以便于用来确保 APK 文件不会被人随意修改。