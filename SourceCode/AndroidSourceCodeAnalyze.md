# 安卓源码分析

## 前言

在安卓中将壳按照发展进度分为一二三代壳，其中一二代壳是通过修改安卓源码中的加载器以及装载类的代码实现的，所以为了弄清楚加壳以及脱壳的原理就需要对相应部分的源码有所了解。

因为 Dalvik 和 Art 实现的原理不同，所以对于 Dalvik 和 Art 两个虚拟机中加载器与 loadClass 的实现都会进行分析。

## 生命周期

一个Java类从开始到结束整个生命周期会经历7个阶段：加载（Loading）、验证（Verification）、准备（Preparation）、解析（Resolution）、初始化（Initialization）、使用（Using）和卸载（Unloading）。其中验证、准备、解析三个部分又统称为连接（Linking）。

下面我们主要分析的就是加载部分。

## Dalvik

### 加载器

下面分别是三个加载器的构造函数，可以发现三个用于加载 Dex 文件的加载器都是直接调用父类的构造函数，只不过传入的参数是不相同的。

```java
public class DexClassLoader extends BaseDexClassLoader {
    public DexClassLoader(String dexPath, String optimizedDirectory,
            String libraryPath, ClassLoader parent) {
        super(dexPath, new File(optimizedDirectory), libraryPath, parent);
    }
}

public class PathClassLoader extends BaseDexClassLoader {
    public PathClassLoader(String dexPath, ClassLoader parent) {
        super(dexPath, null, null, parent);
    }

    PathClassLoader(String dexPath, String libraryPath,
            ClassLoader parent) {
        super(dexPath, null, libraryPath, parent);
    }
}

public final class InMemoryDexClassLoader extends BaseDexClassLoader {
    public InMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent) {
        super(dexBuffers, parent);
    }

    public InMemoryDexClassLoader(ByteBuffer dexBuffer, ClassLoader parent) {
        this(new ByteBuffer[] { dexBuffer }, parent);
    }
}
```

BaseDexClassLoader 有两个构造函数分别为了处理不同的参数，然后可以看到 BaseDexClassLoader 类的两个构造函数都调用了父类的构造函数，但是没有传入其他的参数，之后也都会创建了一个 DexPathList 对象。

```java
public class BaseDexClassLoader extends ClassLoader {
    public BaseDexClassLoader(String dexPath, File optimizedDirectory,
            String librarySearchPath, ClassLoader parent) {
        super(parent);
        this.pathList = new DexPathList(this, dexPath, librarySearchPath, null);

        if (reporter != null) {
            reporter.report(this.pathList.getDexPaths());
        }
    }

    public BaseDexClassLoader(ByteBuffer[] dexFiles, ClassLoader parent) {
        super(parent);
        this.pathList = new DexPathList(this, dexFiles);
    }
}
```

DexPathList 会首先检查一下传进来的参数，检查完之后会调用 makeDexElements 来处理传进来的 dexPath 。

```java
public DexPathList(ClassLoader definingContext, String dexPath,
		String libraryPath, File optimizedDirectory) {
	if (definingContext == null) {
		throw new NullPointerException("definingContext == null");
	}

	if (dexPath == null) {
		throw new NullPointerException("dexPath == null");
	}

	if (optimizedDirectory != null) {
		if (!optimizedDirectory.exists())  {
			throw new IllegalArgumentException(
					"optimizedDirectory doesn't exist: "
					+ optimizedDirectory);
		}

		if (!(optimizedDirectory.canRead()
						&& optimizedDirectory.canWrite())) {
			throw new IllegalArgumentException(
					"optimizedDirectory not readable/writable: "
					+ optimizedDirectory);
		}
	}

	this.definingContext = definingContext;
	ArrayList<IOException> suppressedExceptions = new ArrayList<IOException>();
	this.dexElements = makeDexElements(splitDexPath(dexPath), optimizedDirectory,
										suppressedExceptions);
	if (suppressedExceptions.size() > 0) {
		this.dexElementsSuppressedExceptions =
			suppressedExceptions.toArray(new IOException[suppressedExceptions.size()]);
	} else {
		dexElementsSuppressedExceptions = null;
	}
	this.nativeLibraryDirectories = splitLibraryPath(libraryPath);
}
```

makeDexElements 会对传进来的每个 DexFile 进行处理，主要就是检查一下文件属性以及文件的后缀，然后会调用 loadDexFile 来继续处理 DexFile 。

```java
private static Element[] makeDexElements(ArrayList<File> files, File optimizedDirectory,
											ArrayList<IOException> suppressedExceptions) {
	ArrayList<Element> elements = new ArrayList<Element>();

	for (File file : files) {
		File zip = null;
		DexFile dex = null;
		String name = file.getName();

		if (name.endsWith(DEX_SUFFIX)) {
			// Raw dex file (not inside a zip/jar).
			try {
				dex = loadDexFile(file, optimizedDirectory);
			} catch (IOException ex) {
				System.logE("Unable to load dex file: " + file, ex);
			}
		} else if (name.endsWith(APK_SUFFIX) || name.endsWith(JAR_SUFFIX)
				|| name.endsWith(ZIP_SUFFIX)) {
			zip = file;

			try {
				dex = loadDexFile(file, optimizedDirectory);
			} catch (IOException suppressed) {
				suppressedExceptions.add(suppressed);
			}
		} else if (file.isDirectory()) {
			elements.add(new Element(file, true, null, null));
		} else {
			System.logW("Unknown file type for: " + file);
		}

		if ((zip != null) || (dex != null)) {
			elements.add(new Element(file, false, zip, dex));
		}
	}

	return elements.toArray(new Element[elements.size()]);
}
```

loadDexFile 会先检查是否设置了存放优化后的 odex 的目录，如果有的话就调用 loadDex 来继续加载 Dex 文件，如果没有的话则直接创建一个 DexFile 对象。

```java
private static DexFile loadDexFile(File file, File optimizedDirectory)
		throws IOException {
	if (optimizedDirectory == null) {
		return new DexFile(file);
	} else {
		String optimizedPath = optimizedPathFor(file, optimizedDirectory);
		return DexFile.loadDex(file.getPath(), optimizedPath, 0);
	}
}
```

loadDex 函数会直接创建一个新的 DexFile 对象，与 loadDexFile 中创建 DexFile 对象所传递的参数不一样。

```java
static public DexFile loadDex(String sourcePathName, String outputPathName,
	int flags) throws IOException {

	/*
		* TODO: we may want to cache previously-opened DexFile objects.
		* The cache would be synchronized with close().  This would help
		* us avoid mapping the same DEX more than once when an app
		* decided to open it multiple times.  In practice this may not
		* be a real issue.
		*/
	return new DexFile(sourcePathName, outputPathName, flags);
}
```

DexFile 的构造函数有三个但是最后都会转为调用 `public DexFile(String fileName) throws IOException` 这个构造函数，该构造函数会调用 openDexFile 。

```java
public final class DexFile {
    private int mCookie;
    private final String mFileName;
    private final CloseGuard guard = CloseGuard.get();

    public DexFile(File file) throws IOException {
        this(file.getPath());
    }

    public DexFile(String fileName) throws IOException {
        mCookie = openDexFile(fileName, null, 0);
        mFileName = fileName;
        guard.open("close");
    }

    private DexFile(String sourceName, String outputName, int flags) throws IOException {
        if (outputName != null) {
            try {
                String parent = new File(outputName).getParent();
                if (Libcore.os.getuid() != Libcore.os.stat(parent).st_uid) {
                    throw new IllegalArgumentException("Optimized data directory " + parent
                            + " is not owned by the current user. Shared storage cannot protect"
                            + " your application from code injection attacks.");
                }
            } catch (ErrnoException ignored) {
                // assume we'll fail with a more contextual error later
            }
        }

        mCookie = openDexFile(sourceName, outputName, flags);
        mFileName = sourceName;
        guard.open("close");
    }
```

openDexFile 是 Native 层的一个函数，也就是用 C++ 代码写的，它位于 /dalvik/vm/native/dalvik_system_DexFile.cpp 文件内。

```java
private static int openDexFile(String sourceName, String outputName,
	int flags) throws IOException {
	return openDexFileNative(new File(sourceName).getCanonicalPath(),
								(outputName == null) ? null : new File(outputName).getCanonicalPath(),
								flags);
}

native private static int openDexFileNative(String sourceName, String outputName,
	int flags) throws IOException;
```

Dalvik_dalvik_system_DexFile_openDexFileNative 函数会首先检测一下传入的输出目录等信息，然后根据文件的后缀来调用不同的函数，当后缀为 dex 时调用 dvmRawDexFileOpen 函数，当后缀为 jar 时调用 dvmJarFileOpen 函数。

```c++
static void Dalvik_dalvik_system_DexFile_openDexFileNative(const u4* args,
    JValue* pResult)
{
    StringObject* sourceNameObj = (StringObject*) args[0];
    StringObject* outputNameObj = (StringObject*) args[1];
    DexOrJar* pDexOrJar = NULL;
    JarFile* pJarFile;
    RawDexFile* pRawDexFile;
    char* sourceName;
    char* outputName;

    if (sourceNameObj == NULL) {
        dvmThrowNullPointerException("sourceName == null");
        RETURN_VOID();
    }

    sourceName = dvmCreateCstrFromString(sourceNameObj);
    if (outputNameObj != NULL)
        outputName = dvmCreateCstrFromString(outputNameObj);
    else
        outputName = NULL;

    /*
     * We have to deal with the possibility that somebody might try to
     * open one of our bootstrap class DEX files.  The set of dependencies
     * will be different, and hence the results of optimization might be
     * different, which means we'd actually need to have two versions of
     * the optimized DEX: one that only knows about part of the boot class
     * path, and one that knows about everything in it.  The latter might
     * optimize field/method accesses based on a class that appeared later
     * in the class path.
     *
     * We can't let the user-defined class loader open it and start using
     * the classes, since the optimized form of the code skips some of
     * the method and field resolution that we would ordinarily do, and
     * we'd have the wrong semantics.
     *
     * We have to reject attempts to manually open a DEX file from the boot
     * class path.  The easiest way to do this is by filename, which works
     * out because variations in name (e.g. "/system/framework/./ext.jar")
     * result in us hitting a different dalvik-cache entry.  It's also fine
     * if the caller specifies their own output file.
     */
    if (dvmClassPathContains(gDvm.bootClassPath, sourceName)) {
        ALOGW("Refusing to reopen boot DEX '%s'", sourceName);
        dvmThrowIOException(
            "Re-opening BOOTCLASSPATH DEX files is not allowed");
        free(sourceName);
        free(outputName);
        RETURN_VOID();
    }

    /*
     * Try to open it directly as a DEX if the name ends with ".dex".
     * If that fails (or isn't tried in the first place), try it as a
     * Zip with a "classes.dex" inside.
     */
    if (hasDexExtension(sourceName)
            && dvmRawDexFileOpen(sourceName, outputName, &pRawDexFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (DEX)", sourceName);

        pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
        pDexOrJar->isDex = true;
        pDexOrJar->pRawDexFile = pRawDexFile;
        pDexOrJar->pDexMemory = NULL;
    } else if (dvmJarFileOpen(sourceName, outputName, &pJarFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (Jar)", sourceName);

        pDexOrJar = (DexOrJar*) malloc(sizeof(DexOrJar));
        pDexOrJar->isDex = false;
        pDexOrJar->pJarFile = pJarFile;
        pDexOrJar->pDexMemory = NULL;
    } else {
        ALOGV("Unable to open DEX file '%s'", sourceName);
        dvmThrowIOException("unable to open DEX file");
    }

    if (pDexOrJar != NULL) {
        pDexOrJar->fileName = sourceName;
        addToDexFileTable(pDexOrJar);
    } else {
        free(sourceName);
    }

    free(outputName);
    RETURN_PTR(pDexOrJar);
}
```

dvmRawDexFileOpen 函数会首先检测一下 dex 文件的魔数，然后获取一下 dex 文件的大小和修改时间等信息，然后创建一个 odex 文件，然后调用 dvmOptimizeDexFile 函数来优化 dex 文件，但是在调用之前 dex 文件是还没有优化过的。

```c++
// dvmRawDexFileOpen:
int dvmRawDexFileOpen(const char* fileName, const char* odexOutputName,
    RawDexFile** ppRawDexFile, bool isBootstrap)
{
    /*
     * TODO: This duplicates a lot of code from dvmJarFileOpen() in
     * JarFile.c. This should be refactored.
     */

    DvmDex* pDvmDex = NULL;
    char* cachedName = NULL;
    int result = -1;
    int dexFd = -1;
    int optFd = -1;
    u4 modTime = 0;
    u4 adler32 = 0;
    size_t fileSize = 0;
    bool newFile = false;
    bool locked = false;

    dexFd = open(fileName, O_RDONLY);
    if (dexFd < 0) goto bail;

    /* If we fork/exec into dexopt, don't let it inherit the open fd. */
    dvmSetCloseOnExec(dexFd);

    if (verifyMagicAndGetAdler32(dexFd, &adler32) < 0) {
        ALOGE("Error with header for %s", fileName);
        goto bail;
    }

    if (getModTimeAndSize(dexFd, &modTime, &fileSize) < 0) {
        ALOGE("Error with stat for %s", fileName);
        goto bail;
    }

    /*
     * See if the cached file matches. If so, optFd will become a reference
     * to the cached file and will have been seeked to just past the "opt"
     * header.
     */

    if (odexOutputName == NULL) {
        cachedName = dexOptGenerateCacheFileName(fileName, NULL);
        if (cachedName == NULL)
            goto bail;
    } else {
        cachedName = strdup(odexOutputName);
    }

    ALOGV("dvmRawDexFileOpen: Checking cache for %s (%s)",
            fileName, cachedName);

    optFd = dvmOpenCachedDexFile(fileName, cachedName, modTime,
        adler32, isBootstrap, &newFile, /*createIfMissing=*/true);

    if (optFd < 0) {
        ALOGI("Unable to open or create cache for %s (%s)",
                fileName, cachedName);
        goto bail;
    }
    locked = true;

    /*
     * If optFd points to a new file (because there was no cached
     * version, or the cached version was stale), generate the
     * optimized DEX. The file descriptor returned is still locked,
     * and is positioned just past the optimization header.
     */
    if (newFile) {
        u8 startWhen, copyWhen, endWhen;
        bool result;
        off_t dexOffset;

        dexOffset = lseek(optFd, 0, SEEK_CUR);
        result = (dexOffset > 0);

        if (result) {
            startWhen = dvmGetRelativeTimeUsec();
            result = copyFileToFile(optFd, dexFd, fileSize) == 0;
            copyWhen = dvmGetRelativeTimeUsec();
        }

        if (result) {
            result = dvmOptimizeDexFile(optFd, dexOffset, fileSize,
                fileName, modTime, adler32, isBootstrap);
        }

        if (!result) {
            ALOGE("Unable to extract+optimize DEX from '%s'", fileName);
            goto bail;
        }

        endWhen = dvmGetRelativeTimeUsec();
        ALOGD("DEX prep '%s': copy in %dms, rewrite %dms",
            fileName,
            (int) (copyWhen - startWhen) / 1000,
            (int) (endWhen - copyWhen) / 1000);
    }

    /*
     * Map the cached version.  This immediately rewinds the fd, so it
     * doesn't have to be seeked anywhere in particular.
     */
    if (dvmDexFileOpenFromFd(optFd, &pDvmDex) != 0) {
        ALOGI("Unable to map cached %s", fileName);
        goto bail;
    }

    if (locked) {
        /* unlock the fd */
        if (!dvmUnlockCachedDexFile(optFd)) {
            /* uh oh -- this process needs to exit or we'll wedge the system */
            ALOGE("Unable to unlock DEX file");
            goto bail;
        }
        locked = false;
    }

    ALOGV("Successfully opened '%s'", fileName);

    *ppRawDexFile = (RawDexFile*) calloc(1, sizeof(RawDexFile));
    (*ppRawDexFile)->cacheFileName = cachedName;
    (*ppRawDexFile)->pDvmDex = pDvmDex;
    cachedName = NULL;      // don't free it below
    result = 0;

bail:
    free(cachedName);
    if (dexFd >= 0) {
        close(dexFd);
    }
    if (optFd >= 0) {
        if (locked)
            (void) dvmUnlockCachedDexFile(optFd);
        close(optFd);
    }
    return result;
}
```

dvmOptimizeDexFile 函数会 fork 出一个子进程，在该进程中初始化一些参数，然后调用 dvalik 中的优化组件，来对 dex 进行优化。

```c++
bool dvmOptimizeDexFile(int fd, off_t dexOffset, long dexLength,
    const char* fileName, u4 modWhen, u4 crc, bool isBootstrap)
{
    const char* lastPart = strrchr(fileName, '/');
    if (lastPart != NULL)
        lastPart++;
    else
        lastPart = fileName;

    ALOGD("DexOpt: --- BEGIN '%s' (bootstrap=%d) ---", lastPart, isBootstrap);

    pid_t pid;

    /*
     * This could happen if something in our bootclasspath, which we thought
     * was all optimized, got rejected.
     */
    if (gDvm.optimizing) {
        ALOGW("Rejecting recursive optimization attempt on '%s'", fileName);
        return false;
    }

    pid = fork();
    if (pid == 0) {
        static const int kUseValgrind = 0;
        static const char* kDexOptBin = "/bin/dexopt";
        static const char* kValgrinder = "/usr/bin/valgrind";
        static const int kFixedArgCount = 10;
        static const int kValgrindArgCount = 5;
        static const int kMaxIntLen = 12;   // '-'+10dig+'\0' -OR- 0x+8dig
        int bcpSize = dvmGetBootPathSize();
        int argc = kFixedArgCount + bcpSize
            + (kValgrindArgCount * kUseValgrind);
        const char* argv[argc+1];             // last entry is NULL
        char values[argc][kMaxIntLen];
        char* execFile;
        const char* androidRoot;
        int flags;

        /* change process groups, so we don't clash with ProcessManager */
        setpgid(0, 0);

        /* full path to optimizer */
        androidRoot = getenv("ANDROID_ROOT");
        if (androidRoot == NULL) {
            ALOGW("ANDROID_ROOT not set, defaulting to /system");
            androidRoot = "/system";
        }
        execFile = (char*)alloca(strlen(androidRoot) + strlen(kDexOptBin) + 1);
        strcpy(execFile, androidRoot);
        strcat(execFile, kDexOptBin);

        /*
         * Create arg vector.
         */
        int curArg = 0;

        if (kUseValgrind) {
            /* probably shouldn't ship the hard-coded path */
            argv[curArg++] = (char*)kValgrinder;
            argv[curArg++] = "--tool=memcheck";
            argv[curArg++] = "--leak-check=yes";        // check for leaks too
            argv[curArg++] = "--leak-resolution=med";   // increase from 2 to 4
            argv[curArg++] = "--num-callers=16";        // default is 12
            assert(curArg == kValgrindArgCount);
        }
        argv[curArg++] = execFile;

        argv[curArg++] = "--dex";

        sprintf(values[2], "%d", DALVIK_VM_BUILD);
        argv[curArg++] = values[2];

        sprintf(values[3], "%d", fd);
        argv[curArg++] = values[3];

        sprintf(values[4], "%d", (int) dexOffset);
        argv[curArg++] = values[4];

        sprintf(values[5], "%d", (int) dexLength);
        argv[curArg++] = values[5];

        argv[curArg++] = (char*)fileName;

        sprintf(values[7], "%d", (int) modWhen);
        argv[curArg++] = values[7];

        sprintf(values[8], "%d", (int) crc);
        argv[curArg++] = values[8];

        flags = 0;
        if (gDvm.dexOptMode != OPTIMIZE_MODE_NONE) {
            flags |= DEXOPT_OPT_ENABLED;
            if (gDvm.dexOptMode == OPTIMIZE_MODE_ALL)
                flags |= DEXOPT_OPT_ALL;
        }
        if (gDvm.classVerifyMode != VERIFY_MODE_NONE) {
            flags |= DEXOPT_VERIFY_ENABLED;
            if (gDvm.classVerifyMode == VERIFY_MODE_ALL)
                flags |= DEXOPT_VERIFY_ALL;
        }
        if (isBootstrap)
            flags |= DEXOPT_IS_BOOTSTRAP;
        if (gDvm.generateRegisterMaps)
            flags |= DEXOPT_GEN_REGISTER_MAPS;
        sprintf(values[9], "%d", flags);
        argv[curArg++] = values[9];

        assert(((!kUseValgrind && curArg == kFixedArgCount) ||
               ((kUseValgrind && curArg == kFixedArgCount+kValgrindArgCount))));

        ClassPathEntry* cpe;
        for (cpe = gDvm.bootClassPath; cpe->ptr != NULL; cpe++) {
            argv[curArg++] = cpe->fileName;
        }
        assert(curArg == argc);

        argv[curArg] = NULL;

        if (kUseValgrind)
            execv(kValgrinder, const_cast<char**>(argv));
        else
            execv(execFile, const_cast<char**>(argv));

        ALOGE("execv '%s'%s failed: %s", execFile,
            kUseValgrind ? " [valgrind]" : "", strerror(errno));
        exit(1);
    } else {
        ALOGV("DexOpt: waiting for verify+opt, pid=%d", (int) pid);
        int status;
        pid_t gotPid;

        /*
         * Wait for the optimization process to finish.  We go into VMWAIT
         * mode here so GC suspension won't have to wait for us.
         */
        ThreadStatus oldStatus = dvmChangeStatus(NULL, THREAD_VMWAIT);
        while (true) {
            gotPid = waitpid(pid, &status, 0);
            if (gotPid == -1 && errno == EINTR) {
                ALOGD("waitpid interrupted, retrying");
            } else {
                break;
            }
        }
        dvmChangeStatus(NULL, oldStatus);
        if (gotPid != pid) {
            ALOGE("waitpid failed: wanted %d, got %d: %s",
                (int) pid, (int) gotPid, strerror(errno));
            return false;
        }

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            ALOGD("DexOpt: --- END '%s' (success) ---", lastPart);
            return true;
        } else {
            ALOGW("DexOpt: --- END '%s' --- status=0x%04x, process failed",
                lastPart, status);
            return false;
        }
    }
}
```

这之后会将已经打开对 dex 文件存在一个列表中，用以防止两次打开同一个 dex 文件。

### loadClass

根据 findClass 的注释可以知道当调用 loadClass 没有找到参数中指定的类时会调用 findClass 函数来寻找参数中指定的类，但是 findClass 在 ClassLoader 类中没有实现，因为其要求继承它的子类必须实现相应的 findClass 方法。

```java
protected Class<?> loadClass(String className, boolean resolve) throws ClassNotFoundException {
    Class<?> clazz = findLoadedClass(className);

    if (clazz == null) {
        try {
            clazz = parent.loadClass(className, false);
        } catch (ClassNotFoundException e) {
            // Don't want to see this.
        }

        if (clazz == null) {
            clazz = findClass(className);
        }
    }

    return clazz;
}

/**
    * Overridden by subclasses, throws a {@code ClassNotFoundException} by
    * default. This method is called by {@code loadClass} after the parent
    * {@code ClassLoader} has failed to find a loaded class of the same name.
    *
    * @param className
    *            the name of the class to look for.
    * @return the {@code Class} object that is found.
    * @throws ClassNotFoundException
    *             if the class cannot be found.
    */
protected Class<?> findClass(String className) throws ClassNotFoundException {
    throw new ClassNotFoundException(className);
}
```

下面的 findClass 是 BaseClassLoader 中重载的 findClass ，其会调用 DexPathList 类的 findClass 函数。

```java
@Override
protected Class<?> findClass(String name) throws ClassNotFoundException {
    List<Throwable> suppressedExceptions = new ArrayList<Throwable>();
    Class c = pathList.findClass(name, suppressedExceptions);
    if (c == null) {
        ClassNotFoundException cnfe = new ClassNotFoundException("Didn't find class \"" + name + "\" on path: " + pathList);
        for (Throwable t : suppressedExceptions) {
            cnfe.addSuppressed(t);
        }
        throw cnfe;
    }
    return c;
}
```

findClass 函数会对已经装载过的 dex 文件进行遍历，对每个 dex 文件都会调用 loadClassBinaryName 。

```java
public Class findClass(String name, List<Throwable> suppressed) {
    for (Element element : dexElements) {
        DexFile dex = element.dexFile;

        if (dex != null) {
            Class clazz = dex.loadClassBinaryName(name, definingContext, suppressed);
            if (clazz != null) {
                return clazz;
            }
        }
    }
    if (dexElementsSuppressedExceptions != null) {
        suppressed.addAll(Arrays.asList(dexElementsSuppressedExceptions));
    }
    return null;
}
```

loadClassBinaryName 会调用 defineClass 函数，然后在 defineClass 内部会调用 defineClassNative 函数，defineClassNative 是一个 Native 层的函数。

```java
public Class loadClassBinaryName(String name, ClassLoader loader, List<Throwable> suppressed) {
    return defineClass(name, loader, mCookie, suppressed);
}

private static Class defineClass(String name, ClassLoader loader, int cookie,
                                    List<Throwable> suppressed) {
    Class result = null;
    try {
        result = defineClassNative(name, loader, cookie);
    } catch (NoClassDefFoundError e) {
        if (suppressed != null) {
            suppressed.add(e);
        }
    } catch (ClassNotFoundException e) {
        if (suppressed != null) {
            suppressed.add(e);
        }
    }
    return result;
}
```

对应的 Native 层函数首先会检测是否为 dex 如果为 dex 则调用 dvmGetRawDexFileDex 函数，dvmGetRawDexFileDex 函数仅仅是返回穿进去的参数的 pDvmDex 字段，然后调用 dvmDefineClass 函数。

```C++
static void Dalvik_dalvik_system_DexFile_defineClassNative(const u4* args,
    JValue* pResult)
{
    StringObject* nameObj = (StringObject*) args[0];
    Object* loader = (Object*) args[1];
    int cookie = args[2];
    ClassObject* clazz = NULL;
    DexOrJar* pDexOrJar = (DexOrJar*) cookie;
    DvmDex* pDvmDex;
    char* name;
    char* descriptor;

    name = dvmCreateCstrFromString(nameObj);
    descriptor = dvmDotToDescriptor(name);
    ALOGV("--- Explicit class load '%s' l=%p c=0x%08x",
        descriptor, loader, cookie);
    free(name);

    if (!validateCookie(cookie))
        RETURN_VOID();

    if (pDexOrJar->isDex)
        pDvmDex = dvmGetRawDexFileDex(pDexOrJar->pRawDexFile);
    else
        pDvmDex = dvmGetJarFileDex(pDexOrJar->pJarFile);

    /* once we load something, we can't unmap the storage */
    pDexOrJar->okayToFree = false;

    clazz = dvmDefineClass(pDvmDex, descriptor, loader);
    Thread* self = dvmThreadSelf();
    if (dvmCheckException(self)) {
        /*
         * If we threw a "class not found" exception, stifle it, since the
         * contract in the higher method says we simply return null if
         * the class is not found.
         */
        Object* excep = dvmGetException(self);
        if (strcmp(excep->clazz->descriptor,
                   "Ljava/lang/ClassNotFoundException;") == 0 ||
            strcmp(excep->clazz->descriptor,
                   "Ljava/lang/NoClassDefFoundError;") == 0)
        {
            dvmClearException(self);
        }
        clazz = NULL;
    }

    free(descriptor);
    RETURN_PTR(clazz);
}
```

dvmDefineClass 很简单直接调用了 findClassNoInit 函数。

```C++
ClassObject* dvmDefineClass(DvmDex* pDvmDex, const char* descriptor,
    Object* classLoader)
{
    assert(pDvmDex != NULL);

    return findClassNoInit(descriptor, classLoader, pDvmDex);
}
```

findClassNoInit 函数会调用 dvmLookupClass 来寻找 class 但是首次调用时因为 class 还未被加载所以其会返回 NULL ，返回 NULL 的话就会转而调用 dexFindClass 函数，来继续寻找。

```C++
static ClassObject* findClassNoInit(const char* descriptor, Object* loader,
    DvmDex* pDvmDex)
{
    Thread* self = dvmThreadSelf();
    ClassObject* clazz;
    bool profilerNotified = false;

    if (loader != NULL) {
        LOGVV("#### findClassNoInit(%s,%p,%p)", descriptor, loader,
            pDvmDex->pDexFile);
    }

    /*
     * We don't expect an exception to be raised at this point.  The
     * exception handling code is good about managing this.  This *can*
     * happen if a JNI lookup fails and the JNI code doesn't do any
     * error checking before doing another class lookup, so we may just
     * want to clear this and restore it on exit.  If we don't, some kinds
     * of failures can't be detected without rearranging other stuff.
     *
     * Most often when we hit this situation it means that something is
     * broken in the VM or in JNI code, so I'm keeping it in place (and
     * making it an informative abort rather than an assert).
     */
    if (dvmCheckException(self)) {
        ALOGE("Class lookup %s attempted with exception pending", descriptor);
        ALOGW("Pending exception is:");
        dvmLogExceptionStackTrace();
        dvmDumpAllThreads(false);
        dvmAbort();
    }

    clazz = dvmLookupClass(descriptor, loader, true);
    if (clazz == NULL) {
        const DexClassDef* pClassDef;

        dvmMethodTraceClassPrepBegin();
        profilerNotified = true;

#if LOG_CLASS_LOADING
        u8 startTime = dvmGetThreadCpuTimeNsec();
#endif

        if (pDvmDex == NULL) {
            assert(loader == NULL);     /* shouldn't be here otherwise */
            pDvmDex = searchBootPathForClass(descriptor, &pClassDef);
        } else {
            pClassDef = dexFindClass(pDvmDex->pDexFile, descriptor);
        }

        if (pDvmDex == NULL || pClassDef == NULL) {
            if (gDvm.noClassDefFoundErrorObj != NULL) {
                /* usual case -- use prefabricated object */
                dvmSetException(self, gDvm.noClassDefFoundErrorObj);
            } else {
                /* dexopt case -- can't guarantee prefab (core.jar) */
                dvmThrowNoClassDefFoundError(descriptor);
            }
            goto bail;
        }

        /* found a match, try to load it */
        clazz = loadClassFromDex(pDvmDex, pClassDef, loader);
        if (dvmCheckException(self)) {
            /* class was found but had issues */
            if (clazz != NULL) {
                dvmFreeClassInnards(clazz);
                dvmReleaseTrackedAlloc((Object*) clazz, NULL);
            }
            goto bail;
        }

        /*
         * Lock the class while we link it so other threads must wait for us
         * to finish.  Set the "initThreadId" so we can identify recursive
         * invocation.  (Note all accesses to initThreadId here are
         * guarded by the class object's lock.)
         */
        dvmLockObject(self, (Object*) clazz);
        clazz->initThreadId = self->threadId;

        /*
         * Add to hash table so lookups succeed.
         *
         * [Are circular references possible when linking a class?]
         */
        assert(clazz->classLoader == loader);
        if (!dvmAddClassToHash(clazz)) {
            /*
             * Another thread must have loaded the class after we
             * started but before we finished.  Discard what we've
             * done and leave some hints for the GC.
             *
             * (Yes, this happens.)
             */
            //ALOGW("WOW: somebody loaded %s simultaneously", descriptor);
            clazz->initThreadId = 0;
            dvmUnlockObject(self, (Object*) clazz);

            /* Let the GC free the class.
             */
            dvmFreeClassInnards(clazz);
            dvmReleaseTrackedAlloc((Object*) clazz, NULL);

            /* Grab the winning class.
             */
            clazz = dvmLookupClass(descriptor, loader, true);
            assert(clazz != NULL);
            goto got_class;
        }
        dvmReleaseTrackedAlloc((Object*) clazz, NULL);

#if LOG_CLASS_LOADING
        logClassLoadWithTime('>', clazz, startTime);
#endif
        /*
         * Prepare and resolve.
         */
        if (!dvmLinkClass(clazz)) {
            assert(dvmCheckException(self));

            /* Make note of the error and clean up the class.
             */
            removeClassFromHash(clazz);
            clazz->status = CLASS_ERROR;
            dvmFreeClassInnards(clazz);

            /* Let any waiters know.
             */
            clazz->initThreadId = 0;
            dvmObjectNotifyAll(self, (Object*) clazz);
            dvmUnlockObject(self, (Object*) clazz);

#if LOG_CLASS_LOADING
            ALOG(LOG_INFO, "DVMLINK FAILED FOR CLASS ", "%s in %s",
                clazz->descriptor, get_process_name());

            /*
             * TODO: It would probably be better to use a new type code here (instead of '<') to
             * indicate the failure.  This change would require a matching change in the parser
             * and analysis code in frameworks/base/tools/preload.
             */
            logClassLoad('<', clazz);
#endif
            clazz = NULL;
            if (gDvm.optimizing) {
                /* happens with "external" libs */
                ALOGV("Link of class '%s' failed", descriptor);
            } else {
                ALOGW("Link of class '%s' failed", descriptor);
            }
            goto bail;
        }
        dvmObjectNotifyAll(self, (Object*) clazz);
        dvmUnlockObject(self, (Object*) clazz);

        /*
         * Add class stats to global counters.
         *
         * TODO: these should probably be atomic ops.
         */
        gDvm.numLoadedClasses++;
        gDvm.numDeclaredMethods +=
            clazz->virtualMethodCount + clazz->directMethodCount;
        gDvm.numDeclaredInstFields += clazz->ifieldCount;
        gDvm.numDeclaredStaticFields += clazz->sfieldCount;

        /*
         * Cache pointers to basic classes.  We want to use these in
         * various places, and it's easiest to initialize them on first
         * use rather than trying to force them to initialize (startup
         * ordering makes it weird).
         */
        if (gDvm.classJavaLangObject == NULL &&
            strcmp(descriptor, "Ljava/lang/Object;") == 0)
        {
            /* It should be impossible to get here with anything
             * but the bootclasspath loader.
             */
            assert(loader == NULL);
            gDvm.classJavaLangObject = clazz;
        }

#if LOG_CLASS_LOADING
        logClassLoad('<', clazz);
#endif

    } else {
got_class:
        if (!dvmIsClassLinked(clazz) && clazz->status != CLASS_ERROR) {
            /*
             * We can race with other threads for class linking.  We should
             * never get here recursively; doing so indicates that two
             * classes have circular dependencies.
             *
             * One exception: we force discovery of java.lang.Class in
             * dvmLinkClass(), and Class has Object as its superclass.  So
             * if the first thing we ever load is Object, we will init
             * Object->Class->Object.  The easiest way to avoid this is to
             * ensure that Object is never the first thing we look up, so
             * we get Foo->Class->Object instead.
             */
            dvmLockObject(self, (Object*) clazz);
            if (!dvmIsClassLinked(clazz) &&
                clazz->initThreadId == self->threadId)
            {
                ALOGW("Recursive link on class %s", clazz->descriptor);
                dvmUnlockObject(self, (Object*) clazz);
                dvmThrowClassCircularityError(clazz->descriptor);
                clazz = NULL;
                goto bail;
            }
            //ALOGI("WAITING  for '%s' (owner=%d)",
            //    clazz->descriptor, clazz->initThreadId);
            while (!dvmIsClassLinked(clazz) && clazz->status != CLASS_ERROR) {
                dvmObjectWait(self, (Object*) clazz, 0, 0, false);
            }
            dvmUnlockObject(self, (Object*) clazz);
        }
        if (clazz->status == CLASS_ERROR) {
            /*
             * Somebody else tried to load this and failed.  We need to raise
             * an exception and report failure.
             */
            throwEarlierClassFailure(clazz);
            clazz = NULL;
            goto bail;
        }
    }

    /* check some invariants */
    assert(dvmIsClassLinked(clazz));
    assert(gDvm.classJavaLangClass != NULL);
    assert(clazz->clazz == gDvm.classJavaLangClass);
    assert(dvmIsClassObject(clazz));
    assert(clazz == gDvm.classJavaLangObject || clazz->super != NULL);
    if (!dvmIsInterfaceClass(clazz)) {
        //ALOGI("class=%s vtableCount=%d, virtualMeth=%d",
        //    clazz->descriptor, clazz->vtableCount,
        //    clazz->virtualMethodCount);
        assert(clazz->vtableCount >= clazz->virtualMethodCount);
    }

bail:
    if (profilerNotified)
        dvmMethodTraceClassPrepEnd();
    assert(clazz != NULL || dvmCheckException(self));
    return clazz;
}
```

dexFindClass 函数会对 Dex 文件进行遍历，如果找到了参数中传递的类就用 DexFile 结构体中存储的信息，找到该类在 Dex 文件中的位置。

## Art

### 加载器

Art 比 Dalvik 多了一个 InMemoryClassLoader 加载器，但是我们首先来分析一下 Art 下 DexClassLoader 与 Dalvik 的 DexClassLoader 之间的区别。下面的源码只会贴不相同的部分，相同的部分就直接略过了。

在 openDexFile 函数中会直接调用 jni 函数 DexFile_openDexFileNative ，在这之前 Art 的 DexClassLoader 与 Dalvik 的 DexClassLoader 基本没有区别，但是 openDexFile 所调用的 Native 层函数的实现是不同的。在 DexFile_openDexFileNative 中会调用 OatFileManager 的 OpenDexFilesFromOat 函数来打开 dex 文件。

```C++
static jobject DexFile_openDexFileNative(JNIEnv* env,
                                         jclass,
                                         jstring javaSourceName,
                                         jstring javaOutputName ATTRIBUTE_UNUSED,
                                         jint flags ATTRIBUTE_UNUSED,
                                         jobject class_loader,
                                         jobjectArray dex_elements) {
  ScopedUtfChars sourceName(env, javaSourceName);
  if (sourceName.c_str() == nullptr) {
    return 0;
  }

  Runtime* const runtime = Runtime::Current();
  ClassLinker* linker = runtime->GetClassLinker();
  std::vector<std::unique_ptr<const DexFile>> dex_files;
  std::vector<std::string> error_msgs;
  const OatFile* oat_file = nullptr;

  dex_files = runtime->GetOatFileManager().OpenDexFilesFromOat(sourceName.c_str(),
                                                               class_loader,
                                                               dex_elements,
                                                               /*out*/ &oat_file,
                                                               /*out*/ &error_msgs);

  if (!dex_files.empty()) {
    jlongArray array = ConvertDexFilesToJavaArray(env, oat_file, dex_files);
    if (array == nullptr) {
      ScopedObjectAccess soa(env);
      for (auto& dex_file : dex_files) {
        if (linker->IsDexFileRegistered(soa.Self(), *dex_file)) {
          dex_file.release();
        }
      }
    }
    return array;
  } else {
    ScopedObjectAccess soa(env);
    CHECK(!error_msgs.empty());
    // The most important message is at the end. So set up nesting by going forward, which will
    // wrap the existing exception as a cause for the following one.
    auto it = error_msgs.begin();
    auto itEnd = error_msgs.end();
    for ( ; it != itEnd; ++it) {
      ThrowWrappedIOException("%s", it->c_str());
    }

    return nullptr;
  }
}
```

OpenDexFilesFromOat 函数回首先创建一个 OatFileAssistant 对象，然后利用该对象获取到存储在磁盘上的 oat 文件，然后会进行一系列的检测，过了检测之后会调用 AddImageSpace 来加载 dex 文件。

```C++
std::vector<std::unique_ptr<const DexFile>> OatFileManager::OpenDexFilesFromOat(
    const char* dex_location,
    jobject class_loader,
    jobjectArray dex_elements,
    const OatFile** out_oat_file,
    std::vector<std::string>* error_msgs) {
  ScopedTrace trace(__FUNCTION__);
  CHECK(dex_location != nullptr);
  CHECK(error_msgs != nullptr);

  // Verify we aren't holding the mutator lock, which could starve GC if we
  // have to generate or relocate an oat file.
  Thread* const self = Thread::Current();
  Locks::mutator_lock_->AssertNotHeld(self);
  Runtime* const runtime = Runtime::Current();

  OatFileAssistant oat_file_assistant(dex_location,
                                      kRuntimeISA,
                                      !runtime->IsAotCompiler());

  // Lock the target oat location to avoid races generating and loading the
  // oat file.
  std::string error_msg;
  if (!oat_file_assistant.Lock(/*out*/&error_msg)) {
    // Don't worry too much if this fails. If it does fail, it's unlikely we
    // can generate an oat file anyway.
    VLOG(class_linker) << "OatFileAssistant::Lock: " << error_msg;
  }

  const OatFile* source_oat_file = nullptr;

  if (!oat_file_assistant.IsUpToDate()) {
    // Update the oat file on disk if we can, based on the --compiler-filter
    // option derived from the current runtime options.
    // This may fail, but that's okay. Best effort is all that matters here.
    switch (oat_file_assistant.MakeUpToDate(/*profile_changed*/false, /*out*/ &error_msg)) {
      case OatFileAssistant::kUpdateFailed:
        LOG(WARNING) << error_msg;
        break;

      case OatFileAssistant::kUpdateNotAttempted:
        // Avoid spamming the logs if we decided not to attempt making the oat
        // file up to date.
        VLOG(oat) << error_msg;
        break;

      case OatFileAssistant::kUpdateSucceeded:
        // Nothing to do.
        break;
    }
  }

  // Get the oat file on disk.
  std::unique_ptr<const OatFile> oat_file(oat_file_assistant.GetBestOatFile().release());

  if (oat_file != nullptr) {
    // Take the file only if it has no collisions, or we must take it because of preopting.
    bool accept_oat_file =
        !HasCollisions(oat_file.get(), class_loader, dex_elements, /*out*/ &error_msg);
    if (!accept_oat_file) {
      // Failed the collision check. Print warning.
      if (Runtime::Current()->IsDexFileFallbackEnabled()) {
        if (!oat_file_assistant.HasOriginalDexFiles()) {
          // We need to fallback but don't have original dex files. We have to
          // fallback to opening the existing oat file. This is potentially
          // unsafe so we warn about it.
          accept_oat_file = true;

          LOG(WARNING) << "Dex location " << dex_location << " does not seem to include dex file. "
                       << "Allow oat file use. This is potentially dangerous.";
        } else {
          // We have to fallback and found original dex files - extract them from an APK.
          // Also warn about this operation because it's potentially wasteful.
          LOG(WARNING) << "Found duplicate classes, falling back to extracting from APK : "
                       << dex_location;
          LOG(WARNING) << "NOTE: This wastes RAM and hurts startup performance.";
        }
      } else {
        // TODO: We should remove this. The fact that we're here implies -Xno-dex-file-fallback
        // was set, which means that we should never fallback. If we don't have original dex
        // files, we should just fail resolution as the flag intended.
        if (!oat_file_assistant.HasOriginalDexFiles()) {
          accept_oat_file = true;
        }

        LOG(WARNING) << "Found duplicate classes, dex-file-fallback disabled, will be failing to "
                        " load classes for " << dex_location;
      }

      LOG(WARNING) << error_msg;
    }

    if (accept_oat_file) {
      VLOG(class_linker) << "Registering " << oat_file->GetLocation();
      source_oat_file = RegisterOatFile(std::move(oat_file));
      *out_oat_file = source_oat_file;
    }
  }

  std::vector<std::unique_ptr<const DexFile>> dex_files;

  // Load the dex files from the oat file.
  if (source_oat_file != nullptr) {
    bool added_image_space = false;
    if (source_oat_file->IsExecutable()) {
      std::unique_ptr<gc::space::ImageSpace> image_space =
          kEnableAppImage ? oat_file_assistant.OpenImageSpace(source_oat_file) : nullptr;
      if (image_space != nullptr) {
        ScopedObjectAccess soa(self);
        StackHandleScope<1> hs(self);
        Handle<mirror::ClassLoader> h_loader(
            hs.NewHandle(soa.Decode<mirror::ClassLoader>(class_loader)));
        // Can not load app image without class loader.
        if (h_loader != nullptr) {
          std::string temp_error_msg;
          // Add image space has a race condition since other threads could be reading from the
          // spaces array.
          {
            ScopedThreadSuspension sts(self, kSuspended);
            gc::ScopedGCCriticalSection gcs(self,
                                            gc::kGcCauseAddRemoveAppImageSpace,
                                            gc::kCollectorTypeAddRemoveAppImageSpace);
            ScopedSuspendAll ssa("Add image space");
            runtime->GetHeap()->AddSpace(image_space.get());
          }
          {
            ScopedTrace trace2(StringPrintf("Adding image space for location %s", dex_location));
            added_image_space = runtime->GetClassLinker()->AddImageSpace(image_space.get(),
                                                                         h_loader,
                                                                         dex_elements,
                                                                         dex_location,
                                                                         /*out*/&dex_files,
                                                                         /*out*/&temp_error_msg);
          }
          if (added_image_space) {
            // Successfully added image space to heap, release the map so that it does not get
            // freed.
            image_space.release();
          } else {
            LOG(INFO) << "Failed to add image file " << temp_error_msg;
            dex_files.clear();
            {
              ScopedThreadSuspension sts(self, kSuspended);
              gc::ScopedGCCriticalSection gcs(self,
                                              gc::kGcCauseAddRemoveAppImageSpace,
                                              gc::kCollectorTypeAddRemoveAppImageSpace);
              ScopedSuspendAll ssa("Remove image space");
              runtime->GetHeap()->RemoveSpace(image_space.get());
            }
            // Non-fatal, don't update error_msg.
          }
        }
      }
    }
    if (!added_image_space) {
      DCHECK(dex_files.empty());
      dex_files = oat_file_assistant.LoadDexFiles(*source_oat_file, dex_location);
    }
    if (dex_files.empty()) {
      error_msgs->push_back("Failed to open dex files from " + source_oat_file->GetLocation());
    }
  }

  // Fall back to running out of the original dex file if we couldn't load any
  // dex_files from the oat file.
  if (dex_files.empty()) {
    if (oat_file_assistant.HasOriginalDexFiles()) {
      if (Runtime::Current()->IsDexFileFallbackEnabled()) {
        static constexpr bool kVerifyChecksum = true;
        if (!DexFile::Open(
            dex_location, dex_location, kVerifyChecksum, /*out*/ &error_msg, &dex_files)) {
          LOG(WARNING) << error_msg;
          error_msgs->push_back("Failed to open dex files from " + std::string(dex_location)
                                + " because: " + error_msg);
        }
      } else {
        error_msgs->push_back("Fallback mode disabled, skipping dex files.");
      }
    } else {
      error_msgs->push_back("No original dex files found for dex location "
          + std::string(dex_location));
    }
  }

  return dex_files;
}
```

AddImageSpace 会调用 OpenOatDexFile 函数来打开 dex 文件。

```C++
bool ClassLinker::AddImageSpace(
    gc::space::ImageSpace* space,
    Handle<mirror::ClassLoader> class_loader,
    jobjectArray dex_elements,
    const char* dex_location,
    std::vector<std::unique_ptr<const DexFile>>* out_dex_files,
    std::string* error_msg) {
  DCHECK(out_dex_files != nullptr);
  DCHECK(error_msg != nullptr);
  const uint64_t start_time = NanoTime();
  const bool app_image = class_loader != nullptr;
  const ImageHeader& header = space->GetImageHeader();
  ObjPtr<mirror::Object> dex_caches_object = header.GetImageRoot(ImageHeader::kDexCaches);
  DCHECK(dex_caches_object != nullptr);
  Runtime* const runtime = Runtime::Current();
  gc::Heap* const heap = runtime->GetHeap();
  Thread* const self = Thread::Current();
  // Check that the image is what we are expecting.
  if (image_pointer_size_ != space->GetImageHeader().GetPointerSize()) {
    *error_msg = StringPrintf("Application image pointer size does not match runtime: %zu vs %zu",
                              static_cast<size_t>(space->GetImageHeader().GetPointerSize()),
                              image_pointer_size_);
    return false;
  }
  size_t expected_image_roots = ImageHeader::NumberOfImageRoots(app_image);
  if (static_cast<size_t>(header.GetImageRoots()->GetLength()) != expected_image_roots) {
    *error_msg = StringPrintf("Expected %zu image roots but got %d",
                              expected_image_roots,
                              header.GetImageRoots()->GetLength());
    return false;
  }
  StackHandleScope<3> hs(self);
  Handle<mirror::ObjectArray<mirror::DexCache>> dex_caches(
      hs.NewHandle(dex_caches_object->AsObjectArray<mirror::DexCache>()));
  Handle<mirror::ObjectArray<mirror::Class>> class_roots(hs.NewHandle(
      header.GetImageRoot(ImageHeader::kClassRoots)->AsObjectArray<mirror::Class>()));
  static_assert(ImageHeader::kClassLoader + 1u == ImageHeader::kImageRootsMax,
                "Class loader should be the last image root.");
  MutableHandle<mirror::ClassLoader> image_class_loader(hs.NewHandle(
      app_image ? header.GetImageRoot(ImageHeader::kClassLoader)->AsClassLoader() : nullptr));
  DCHECK(class_roots != nullptr);
  if (class_roots->GetLength() != static_cast<int32_t>(kClassRootsMax)) {
    *error_msg = StringPrintf("Expected %d class roots but got %d",
                              class_roots->GetLength(),
                              static_cast<int32_t>(kClassRootsMax));
    return false;
  }
  // Check against existing class roots to make sure they match the ones in the boot image.
  for (size_t i = 0; i < kClassRootsMax; i++) {
    if (class_roots->Get(i) != GetClassRoot(static_cast<ClassRoot>(i))) {
      *error_msg = "App image class roots must have pointer equality with runtime ones.";
      return false;
    }
  }
  const OatFile* oat_file = space->GetOatFile();
  if (oat_file->GetOatHeader().GetDexFileCount() !=
      static_cast<uint32_t>(dex_caches->GetLength())) {
    *error_msg = "Dex cache count and dex file count mismatch while trying to initialize from "
                 "image";
    return false;
  }

  for (int32_t i = 0; i < dex_caches->GetLength(); i++) {
    ObjPtr<mirror::DexCache> dex_cache = dex_caches->Get(i);
    std::string dex_file_location(dex_cache->GetLocation()->ToModifiedUtf8());
    // TODO: Only store qualified paths.
    // If non qualified, qualify it.
    if (dex_file_location.find('/') == std::string::npos) {
      std::string dex_location_path = dex_location;
      const size_t pos = dex_location_path.find_last_of('/');
      CHECK_NE(pos, std::string::npos);
      dex_location_path = dex_location_path.substr(0, pos + 1);  // Keep trailing '/'
      dex_file_location = dex_location_path + dex_file_location;
    }
    std::unique_ptr<const DexFile> dex_file = OpenOatDexFile(oat_file,
                                                             dex_file_location.c_str(),
                                                             error_msg);
    if (dex_file == nullptr) {
      return false;
    }

    if (app_image) {
      // The current dex file field is bogus, overwrite it so that we can get the dex file in the
      // loop below.
      dex_cache->SetDexFile(dex_file.get());
      mirror::TypeDexCacheType* const types = dex_cache->GetResolvedTypes();
      for (int32_t j = 0, num_types = dex_cache->NumResolvedTypes(); j < num_types; j++) {
        ObjPtr<mirror::Class> klass = types[j].load(std::memory_order_relaxed).object.Read();
        if (klass != nullptr) {
          DCHECK(!klass->IsErroneous()) << klass->GetStatus();
        }
      }
    } else {
      if (kSanityCheckObjects) {
        ImageSanityChecks::CheckPointerArray(heap,
                                             this,
                                             dex_cache->GetResolvedMethods(),
                                             dex_cache->NumResolvedMethods());
      }
      // Register dex files, keep track of existing ones that are conflicts.
      AppendToBootClassPath(*dex_file.get(), dex_cache);
    }
    out_dex_files->push_back(std::move(dex_file));
  }

  if (app_image) {
    ScopedObjectAccessUnchecked soa(Thread::Current());
    // Check that the class loader resolves the same way as the ones in the image.
    // Image class loader [A][B][C][image dex files]
    // Class loader = [???][dex_elements][image dex files]
    // Need to ensure that [???][dex_elements] == [A][B][C].
    // For each class loader, PathClassLoader, the laoder checks the parent first. Also the logic
    // for PathClassLoader does this by looping through the array of dex files. To ensure they
    // resolve the same way, simply flatten the hierarchy in the way the resolution order would be,
    // and check that the dex file names are the same.
    if (IsBootClassLoader(soa, image_class_loader.Get())) {
      *error_msg = "Unexpected BootClassLoader in app image";
      return false;
    }
    std::list<ObjPtr<mirror::String>> image_dex_file_names;
    std::string temp_error_msg;
    if (!FlattenPathClassLoader(image_class_loader.Get(), &image_dex_file_names, &temp_error_msg)) {
      *error_msg = StringPrintf("Failed to flatten image class loader hierarchy '%s'",
                                temp_error_msg.c_str());
      return false;
    }
    std::list<ObjPtr<mirror::String>> loader_dex_file_names;
    if (!FlattenPathClassLoader(class_loader.Get(), &loader_dex_file_names, &temp_error_msg)) {
      *error_msg = StringPrintf("Failed to flatten class loader hierarchy '%s'",
                                temp_error_msg.c_str());
      return false;
    }
    // Add the temporary dex path list elements at the end.
    auto elements = soa.Decode<mirror::ObjectArray<mirror::Object>>(dex_elements);
    for (size_t i = 0, num_elems = elements->GetLength(); i < num_elems; ++i) {
      ObjPtr<mirror::Object> element = elements->GetWithoutChecks(i);
      if (element != nullptr) {
        // If we are somewhere in the middle of the array, there may be nulls at the end.
        ObjPtr<mirror::String> name;
        if (GetDexPathListElementName(element, &name) && name != nullptr) {
          loader_dex_file_names.push_back(name);
        }
      }
    }
    // Ignore the number of image dex files since we are adding those to the class loader anyways.
    CHECK_GE(static_cast<size_t>(image_dex_file_names.size()),
             static_cast<size_t>(dex_caches->GetLength()));
    size_t image_count = image_dex_file_names.size() - dex_caches->GetLength();
    // Check that the dex file names match.
    bool equal = image_count == loader_dex_file_names.size();
    if (equal) {
      auto it1 = image_dex_file_names.begin();
      auto it2 = loader_dex_file_names.begin();
      for (size_t i = 0; equal && i < image_count; ++i, ++it1, ++it2) {
        equal = equal && (*it1)->Equals(*it2);
      }
    }
    if (!equal) {
      VLOG(image) << "Image dex files " << image_dex_file_names.size();
      for (ObjPtr<mirror::String> name : image_dex_file_names) {
        VLOG(image) << name->ToModifiedUtf8();
      }
      VLOG(image) << "Loader dex files " << loader_dex_file_names.size();
      for (ObjPtr<mirror::String> name : loader_dex_file_names) {
        VLOG(image) << name->ToModifiedUtf8();
      }
      *error_msg = "Rejecting application image due to class loader mismatch";
      // Ignore class loader mismatch for now since these would just use possibly incorrect
      // oat code anyways. The structural class check should be done in the parent.
    }
  }

  if (kSanityCheckObjects) {
    for (int32_t i = 0; i < dex_caches->GetLength(); i++) {
      auto* dex_cache = dex_caches->Get(i);
      for (size_t j = 0; j < dex_cache->NumResolvedFields(); ++j) {
        auto* field = dex_cache->GetResolvedField(j, image_pointer_size_);
        if (field != nullptr) {
          CHECK(field->GetDeclaringClass()->GetClass() != nullptr);
        }
      }
    }
    if (!app_image) {
      ImageSanityChecks::CheckObjects(heap, this);
    }
  }

  // Set entry point to interpreter if in InterpretOnly mode.
  if (!runtime->IsAotCompiler() && runtime->GetInstrumentation()->InterpretOnly()) {
    SetInterpreterEntrypointArtMethodVisitor visitor(image_pointer_size_);
    header.VisitPackedArtMethods(&visitor, space->Begin(), image_pointer_size_);
  }

  ClassTable* class_table = nullptr;
  {
    WriterMutexLock mu(self, *Locks::classlinker_classes_lock_);
    class_table = InsertClassTableForClassLoader(class_loader.Get());
  }
  // If we have a class table section, read it and use it for verification in
  // UpdateAppImageClassLoadersAndDexCaches.
  ClassTable::ClassSet temp_set;
  const ImageSection& class_table_section = header.GetImageSection(ImageHeader::kSectionClassTable);
  const bool added_class_table = class_table_section.Size() > 0u;
  if (added_class_table) {
    const uint64_t start_time2 = NanoTime();
    size_t read_count = 0;
    temp_set = ClassTable::ClassSet(space->Begin() + class_table_section.Offset(),
                                    /*make copy*/false,
                                    &read_count);
    VLOG(image) << "Adding class table classes took " << PrettyDuration(NanoTime() - start_time2);
  }
  if (app_image) {
    bool forward_dex_cache_arrays = false;
    if (!UpdateAppImageClassLoadersAndDexCaches(space,
                                                class_loader,
                                                dex_caches,
                                                &temp_set,
                                                /*out*/&forward_dex_cache_arrays,
                                                /*out*/error_msg)) {
      return false;
    }
    // Update class loader and resolved strings. If added_class_table is false, the resolved
    // strings were forwarded UpdateAppImageClassLoadersAndDexCaches.
    UpdateClassLoaderVisitor visitor(space, class_loader.Get());
    for (const ClassTable::TableSlot& root : temp_set) {
      visitor(root.Read());
    }
    // forward_dex_cache_arrays is true iff we copied all of the dex cache arrays into the .bss.
    // In this case, madvise away the dex cache arrays section of the image to reduce RAM usage and
    // mark as PROT_NONE to catch any invalid accesses.
    if (forward_dex_cache_arrays) {
      const ImageSection& dex_cache_section = header.GetImageSection(
          ImageHeader::kSectionDexCacheArrays);
      uint8_t* section_begin = AlignUp(space->Begin() + dex_cache_section.Offset(), kPageSize);
      uint8_t* section_end = AlignDown(space->Begin() + dex_cache_section.End(), kPageSize);
      if (section_begin < section_end) {
        madvise(section_begin, section_end - section_begin, MADV_DONTNEED);
        mprotect(section_begin, section_end - section_begin, PROT_NONE);
        VLOG(image) << "Released and protected dex cache array image section from "
                    << reinterpret_cast<const void*>(section_begin) << "-"
                    << reinterpret_cast<const void*>(section_end);
      }
    }
  }
  if (!oat_file->GetBssGcRoots().empty()) {
    // Insert oat file to class table for visiting .bss GC roots.
    class_table->InsertOatFile(oat_file);
  }
  if (added_class_table) {
    WriterMutexLock mu(self, *Locks::classlinker_classes_lock_);
    class_table->AddClassSet(std::move(temp_set));
  }
  if (kIsDebugBuild && app_image) {
    // This verification needs to happen after the classes have been added to the class loader.
    // Since it ensures classes are in the class table.
    VerifyClassInTableArtMethodVisitor visitor2(class_table);
    header.VisitPackedArtMethods(&visitor2, space->Begin(), kRuntimePointerSize);
    // Verify that all direct interfaces of classes in the class table are also resolved.
    VerifyDirectInterfacesInTableClassVisitor visitor(class_loader.Get());
    class_table->Visit(visitor);
    visitor.Check();
    // Check that all non-primitive classes in dex caches are also in the class table.
    for (int32_t i = 0; i < dex_caches->GetLength(); i++) {
      ObjPtr<mirror::DexCache> dex_cache = dex_caches->Get(i);
      mirror::TypeDexCacheType* const types = dex_cache->GetResolvedTypes();
      for (int32_t j = 0, num_types = dex_cache->NumResolvedTypes(); j < num_types; j++) {
        ObjPtr<mirror::Class> klass = types[j].load(std::memory_order_relaxed).object.Read();
        if (klass != nullptr && !klass->IsPrimitive()) {
          CHECK(class_table->Contains(klass)) << klass->PrettyDescriptor()
              << " " << dex_cache->GetDexFile()->GetLocation();
        }
      }
    }
  }
  VLOG(class_linker) << "Adding image space took " << PrettyDuration(NanoTime() - start_time);
  return true;
}
```

这个函数会调用 OatDexFile 对象的 OpenDexFile 方法，在调用这个方法之前需要先调用 GetOatDexFile 来获取 OatDexFile 对象，获取完成之后才去调用 OpenDexFile 对象，在 OpenDexFile 中会直接调用 DexFile 类的 open 函数来完成打开 dex 文件。

```C++
static std::unique_ptr<const DexFile> OpenOatDexFile(const OatFile* oat_file,
                                                     const char* location,
                                                     std::string* error_msg)
    REQUIRES_SHARED(Locks::mutator_lock_) {
  DCHECK(error_msg != nullptr);
  std::unique_ptr<const DexFile> dex_file;
  const OatFile::OatDexFile* oat_dex_file = oat_file->GetOatDexFile(location, nullptr, error_msg);
  if (oat_dex_file == nullptr) {
    return std::unique_ptr<const DexFile>();
  }
  std::string inner_error_msg;
  dex_file = oat_dex_file->OpenDexFile(&inner_error_msg);
  if (dex_file == nullptr) {
    *error_msg = StringPrintf("Failed to open dex file %s from within oat file %s error '%s'",
                              location,
                              oat_file->GetLocation().c_str(),
                              inner_error_msg.c_str());
    return std::unique_ptr<const DexFile>();
  }

  if (dex_file->GetLocationChecksum() != oat_dex_file->GetDexFileLocationChecksum()) {
    *error_msg = StringPrintf("Checksums do not match for %s: %x vs %x",
                              location,
                              dex_file->GetLocationChecksum(),
                              oat_dex_file->GetDexFileLocationChecksum());
    return std::unique_ptr<const DexFile>();
  }
  return dex_file;
}
```

**/////////////////////////////////////////////////////////////////////////////////**
**////////////////////InMemoryDexClassLoader////////////////////**
**////////////////////////////////////////////////////////////////////////////////**

接下来分析一下 Dalvik 中没有的 InMemoryDexClassLoader 加载器，可以看到它的构造函数还是会调用父类的构造函数。然后在 BaseDexClassLoader 中同样也是会创建一饿 DexPathList 对象，只不过这时候创建的 DexPathList 对象传入的参数变了。

```java
public final class InMemoryDexClassLoader extends BaseDexClassLoader {
    /**
     * Create an in-memory DEX class loader with the given dex buffers.
     *
     * @param dexBuffers array of buffers containing DEX files between
     *                       <tt>buffer.position()</tt> and <tt>buffer.limit()</tt>.
     * @param parent the parent class loader for delegation.
     * @hide
     */
    public InMemoryDexClassLoader(ByteBuffer[] dexBuffers, ClassLoader parent) {
        super(dexBuffers, parent);
    }

    /**
     * Creates a new in-memory DEX class loader.
     *
     * @param dexBuffer buffer containing DEX file contents between
     *                       <tt>buffer.position()</tt> and <tt>buffer.limit()</tt>.
     * @param parent the parent class loader for delegation.
     */
    public InMemoryDexClassLoader(ByteBuffer dexBuffer, ClassLoader parent) {
        this(new ByteBuffer[] { dexBuffer }, parent);
    }
}
```

DexPathList 这里从调用 makeDexElements 而变成了调用 makeInMemoryDexElements 。

```C++
public DexPathList(ClassLoader definingContext, ByteBuffer[] dexFiles) {
    if (definingContext == null) {
        throw new NullPointerException("definingContext == null");
    }
    if (dexFiles == null) {
        throw new NullPointerException("dexFiles == null");
    }
    if (Arrays.stream(dexFiles).anyMatch(v -> v == null)) {
        throw new NullPointerException("dexFiles contains a null Buffer!");
    }

    this.definingContext = definingContext;
    // TODO It might be useful to let in-memory dex-paths have native libraries.
    this.nativeLibraryDirectories = Collections.emptyList();
    this.systemNativeLibraryDirectories =
            splitPaths(System.getProperty("java.library.path"), true);
    this.nativeLibraryPathElements = makePathElements(this.systemNativeLibraryDirectories);

    ArrayList<IOException> suppressedExceptions = new ArrayList<IOException>();
    this.dexElements = makeInMemoryDexElements(dexFiles, suppressedExceptions);
    if (suppressedExceptions.size() > 0) {
        this.dexElementsSuppressedExceptions =
                suppressedExceptions.toArray(new IOException[suppressedExceptions.size()]);
    } else {
        dexElementsSuppressedExceptions = null;
    }
}
```

makeInMemoryDexElements 和 makeDexElements 函数一样会创建出一个 DexFile 文件，

```C++
private static Element[] makeInMemoryDexElements(ByteBuffer[] dexFiles,
        List<IOException> suppressedExceptions) {
    Element[] elements = new Element[dexFiles.length];
    int elementPos = 0;
    for (ByteBuffer buf : dexFiles) {
        try {
            DexFile dex = new DexFile(buf);
            elements[elementPos++] = new Element(dex);
        } catch (IOException suppressed) {
            System.logE("Unable to load dex file: " + buf, suppressed);
            suppressedExceptions.add(suppressed);
        }
    }
    if (elementPos != elements.length) {
        elements = Arrays.copyOf(elements, elementPos);
    }
    return elements;
}
```

Art 中的 DexFile 的构造函数与 Dalvik 中的是不相同的，这里的 DexFile 对应传入一个 ByteBuffer 类型的重载会直接调用 openINopenInMemoryDexFile 函数。

```java
DexFile(ByteBuffer buf) throws IOException {
    mCookie = openInMemoryDexFile(buf);
    mInternalCookie = mCookie;
    mFileName = null;
}
```

openInMemoryDexFile 函数会根据传入的参数是不是目录而选择不同的函数来执行，这里我们只看不是目录的情况。但是这两个函数都是 Native 层的函数。

```java
private static Object openInMemoryDexFile(ByteBuffer buf) throws IOException {
    if (buf.isDirect()) {
        return createCookieWithDirectBuffer(buf, buf.position(), buf.limit());
    } else {
        return createCookieWithArray(buf.array(), buf.position(), buf.limit());
    }
}

private static native Object createCookieWithDirectBuffer(ByteBuffer buf, int start, int end);
private static native Object createCookieWithArray(byte[] buf, int start, int end);
```

这里会 map 一块内存然后放进 env 中存储起来，最后调用 CreateSingleDexFileCookie 函数。

```C++
static jobject DexFile_createCookieWithArray(JNIEnv* env,
                                             jclass,
                                             jbyteArray buffer,
                                             jint start,
                                             jint end) {
  std::unique_ptr<MemMap> dex_mem_map(AllocateDexMemoryMap(env, start, end));
  if (dex_mem_map == nullptr) {
    DCHECK(Thread::Current()->IsExceptionPending());
    return 0;
  }

  auto destination = reinterpret_cast<jbyte*>(dex_mem_map.get()->Begin());
  env->GetByteArrayRegion(buffer, start, end - start, destination);
  return CreateSingleDexFileCookie(env, std::move(dex_mem_map));
}
```

这里会直接调用 CreateDexFile 函数来创建一个 DexFile 对象，然后用一个指针指向创建出来的对象。

```C++
static jobject CreateSingleDexFileCookie(JNIEnv* env, std::unique_ptr<MemMap> data) {
  std::unique_ptr<const DexFile> dex_file(CreateDexFile(env, std::move(data)));
  if (dex_file.get() == nullptr) {
    DCHECK(env->ExceptionCheck());
    return nullptr;
  }
  std::vector<std::unique_ptr<const DexFile>> dex_files;
  dex_files.push_back(std::move(dex_file));
  return ConvertDexFilesToJavaArray(env, nullptr, dex_files);
}
```

CreateDexFile 中又转而去调用 DexFile 的 Open 函数，传入了 5 个参数。

```C++
static const DexFile* CreateDexFile(JNIEnv* env, std::unique_ptr<MemMap> dex_mem_map) {
  std::string location = StringPrintf("Anonymous-DexFile@%p-%p",
                                      dex_mem_map->Begin(),
                                      dex_mem_map->End());
  std::string error_message;
  std::unique_ptr<const DexFile> dex_file(DexFile::Open(location,
                                                        0,
                                                        std::move(dex_mem_map),
                                                        /* verify */ true,
                                                        /* verify_location */ true,
                                                        &error_message));
  if (dex_file == nullptr) {
    ScopedObjectAccess soa(env);
    ThrowWrappedIOException("%s", error_message.c_str());
    return nullptr;
  }

  if (!dex_file->DisableWrite()) {
    ScopedObjectAccess soa(env);
    ThrowWrappedIOException("Failed to make dex file read-only");
    return nullptr;
  }

  return dex_file.release();
}
```

DexFile::Open 会直接调用 OpenCommon 函数。

```C++
std::unique_ptr<const DexFile> DexFile::Open(const uint8_t* base,
                                             size_t size,
                                             const std::string& location,
                                             uint32_t location_checksum,
                                             const OatDexFile* oat_dex_file,
                                             bool verify,
                                             bool verify_checksum,
                                             std::string* error_msg) {
  ScopedTrace trace(std::string("Open dex file from RAM ") + location);
  return OpenCommon(base,
                    size,
                    location,
                    location_checksum,
                    oat_dex_file,
                    verify,
                    verify_checksum,
                    error_msg);
}
```

在 OpenCommon 中会直接创建一个 DexFile 对象，这里就已经把内存中与 Dex 文件相关的信息全部传给了 DexFile 的构造函数，然后返回一个 DexFile 对象，至此 Dex 就从内存中加载进来了。后面就是进行一系列的校验操作。

```C++
std::unique_ptr<DexFile> DexFile::OpenCommon(const uint8_t* base,
                                             size_t size,
                                             const std::string& location,
                                             uint32_t location_checksum,
                                             const OatDexFile* oat_dex_file,
                                             bool verify,
                                             bool verify_checksum,
                                             std::string* error_msg,
                                             VerifyResult* verify_result) {
  if (verify_result != nullptr) {
    *verify_result = VerifyResult::kVerifyNotAttempted;
  }
  std::unique_ptr<DexFile> dex_file(new DexFile(base,
                                                size,
                                                location,
                                                location_checksum,
                                                oat_dex_file));
  if (dex_file == nullptr) {
    *error_msg = StringPrintf("Failed to open dex file '%s' from memory: %s", location.c_str(),
                              error_msg->c_str());
    return nullptr;
  }
  if (!dex_file->Init(error_msg)) {
    dex_file.reset();
    return nullptr;
  }
  if (verify && !DexFileVerifier::Verify(dex_file.get(),
                                         dex_file->Begin(),
                                         dex_file->Size(),
                                         location.c_str(),
                                         verify_checksum,
                                         error_msg)) {
    if (verify_result != nullptr) {
      *verify_result = VerifyResult::kVerifyFailed;
    }
    return nullptr;
  }
  if (verify_result != nullptr) {
    *verify_result = VerifyResult::kVerifySucceeded;
  }
  return dex_file;
}
```

### loadClass

loadClass 最开始的部分和 Dalvik 一样，首先找一下是否已经加载了这个类，加载完之后如果没有找到的话就调用 findClass 并且 findClass 也是要求子类必须实现的。 同样这里只列出与 Dalvik 不同的部分。

Native 层的 defineClassNative 函数是不同的，在这之前的调用链是基本相同的，然后这里调用 ConvertJavaArrayToDexFiles 来找到所有的 dex 文件，找到之后进行一个遍历，遍历时使用 FindClassDef 来找到定义的类然后调用 DefineClass 来找到具体的类。

```C++
static jclass DexFile_defineClassNative(JNIEnv* env,
                                        jclass,
                                        jstring javaName,
                                        jobject javaLoader,
                                        jobject cookie,
                                        jobject dexFile) {
  std::vector<const DexFile*> dex_files;
  const OatFile* oat_file;
  if (!ConvertJavaArrayToDexFiles(env, cookie, /*out*/ dex_files, /*out*/ oat_file)) {
    VLOG(class_linker) << "Failed to find dex_file";
    DCHECK(env->ExceptionCheck());
    return nullptr;
  }

  ScopedUtfChars class_name(env, javaName);
  if (class_name.c_str() == nullptr) {
    VLOG(class_linker) << "Failed to find class_name";
    return nullptr;
  }
  const std::string descriptor(DotToDescriptor(class_name.c_str()));
  const size_t hash(ComputeModifiedUtf8Hash(descriptor.c_str()));
  for (auto& dex_file : dex_files) {
    const DexFile::ClassDef* dex_class_def =
        OatDexFile::FindClassDef(*dex_file, descriptor.c_str(), hash);
    if (dex_class_def != nullptr) {
      ScopedObjectAccess soa(env);
      ClassLinker* class_linker = Runtime::Current()->GetClassLinker();
      StackHandleScope<1> hs(soa.Self());
      Handle<mirror::ClassLoader> class_loader(
          hs.NewHandle(soa.Decode<mirror::ClassLoader>(javaLoader)));
      ObjPtr<mirror::DexCache> dex_cache =
          class_linker->RegisterDexFile(*dex_file, class_loader.Get());
      if (dex_cache == nullptr) {
        // OOME or InternalError (dexFile already registered with a different class loader).
        soa.Self()->AssertPendingException();
        return nullptr;
      }
      ObjPtr<mirror::Class> result = class_linker->DefineClass(soa.Self(),
                                                               descriptor.c_str(),
                                                               hash,
                                                               class_loader,
                                                               *dex_file,
                                                               *dex_class_def);
      // Add the used dex file. This only required for the DexFile.loadClass API since normal
      // class loaders already keep their dex files live.
      class_linker->InsertDexFileInToClassLoader(soa.Decode<mirror::Object>(dexFile),
                                                 class_loader.Get());
      if (result != nullptr) {
        VLOG(class_linker) << "DexFile_defineClassNative returning " << result
                           << " for " << class_name.c_str();
        return soa.AddLocalReference<jclass>(result);
      }
    }
  }
  VLOG(class_linker) << "Failed to find dex_class_def " << class_name.c_str();
  return nullptr;
}
```

DefineClass 会首先预定义一个类，然后这个类会在保存类信息的结构里创建一个空的节点，然后调用 LoadClass 来将类中的字段和一些其他内容放进创建的节点中，最后会调用 LoadSuperAndInterfaces 函数来找到这个类的父类和接口等信息。

```C++
mirror::Class* ClassLinker::DefineClass(Thread* self,
                                        const char* descriptor,
                                        size_t hash,
                                        Handle<mirror::ClassLoader> class_loader,
                                        const DexFile& dex_file,
                                        const DexFile::ClassDef& dex_class_def) {
    StackHandleScope<3> hs(self);
    auto klass = hs.NewHandle<mirror::Class>(nullptr);

    // Load the class from the dex file.
    if (UNLIKELY(!init_done_)) {
        // finish up init of hand crafted class_roots_
        if (strcmp(descriptor, "Ljava/lang/Object;") == 0) {
            klass.Assign(GetClassRoot(kJavaLangObject));
        } else if (strcmp(descriptor, "Ljava/lang/Class;") == 0) {
            klass.Assign(GetClassRoot(kJavaLangClass));
        } else if (strcmp(descriptor, "Ljava/lang/String;") == 0) {
            klass.Assign(GetClassRoot(kJavaLangString));
        } else if (strcmp(descriptor, "Ljava/lang/ref/Reference;") == 0) {
            klass.Assign(GetClassRoot(kJavaLangRefReference));
        } else if (strcmp(descriptor, "Ljava/lang/DexCache;") == 0) {
            klass.Assign(GetClassRoot(kJavaLangDexCache));
        } else if (strcmp(descriptor, "Ldalvik/system/ClassExt;") == 0) {
            klass.Assign(GetClassRoot(kDalvikSystemClassExt));
        }
    }

    if (klass == nullptr) {
        // Allocate a class with the status of not ready.
        // Interface object should get the right size here. Regular class will
        // figure out the right size later and be replaced with one of the right
        // size when the class becomes resolved.
        klass.Assign(AllocClass(self, SizeOfClassWithoutEmbeddedTables(dex_file, dex_class_def)));
    }
    if (UNLIKELY(klass == nullptr)) {
        self->AssertPendingOOMException();
        return nullptr;
    }
    // Get the real dex file. This will return the input if there aren't any callbacks or they do
    // nothing.
    DexFile const* new_dex_file = nullptr;
    DexFile::ClassDef const* new_class_def = nullptr;
    // TODO We should ideally figure out some way to move this after we get a lock on the klass so it
    // will only be called once.
    Runtime::Current()->GetRuntimeCallbacks()->ClassPreDefine(descriptor,
                                                                klass,
                                                                class_loader,
                                                                dex_file,
                                                                dex_class_def,
                                                                &new_dex_file,
                                                                &new_class_def);
    // Check to see if an exception happened during runtime callbacks. Return if so.
    if (self->IsExceptionPending()) {
        return nullptr;
    }
    ObjPtr<mirror::DexCache> dex_cache = RegisterDexFile(*new_dex_file, class_loader.Get());
    if (dex_cache == nullptr) {
        self->AssertPendingException();
        return nullptr;
    }
    klass->SetDexCache(dex_cache);
    SetupClass(*new_dex_file, *new_class_def, klass, class_loader.Get());

    // Mark the string class by setting its access flag.
    if (UNLIKELY(!init_done_)) {
        if (strcmp(descriptor, "Ljava/lang/String;") == 0) {
            klass->SetStringClass();
        }
    }

    ObjectLock<mirror::Class> lock(self, klass);
    klass->SetClinitThreadId(self->GetTid());
    // Make sure we have a valid empty iftable even if there are errors.
    klass->SetIfTable(GetClassRoot(kJavaLangObject)->GetIfTable());

    // Add the newly loaded class to the loaded classes table.
    ObjPtr<mirror::Class> existing = InsertClass(descriptor, klass.Get(), hash);
    if (existing != nullptr) {
        // We failed to insert because we raced with another thread. Calling EnsureResolved may cause
        // this thread to block.
        return EnsureResolved(self, descriptor, existing);
    }

    // Load the fields and other things after we are inserted in the table. This is so that we don't
    // end up allocating unfree-able linear alloc resources and then lose the race condition. The
    // other reason is that the field roots are only visited from the class table. So we need to be
    // inserted before we allocate / fill in these fields.
    LoadClass(self, *new_dex_file, *new_class_def, klass);
    if (self->IsExceptionPending()) {
        VLOG(class_linker) << self->GetException()->Dump();
        // An exception occured during load, set status to erroneous while holding klass' lock in case
        // notification is necessary.
        if (!klass->IsErroneous()) {
            mirror::Class::SetStatus(klass, mirror::Class::kStatusErrorUnresolved, self);
        }
        return nullptr;
    }

    // Finish loading (if necessary) by finding parents
    CHECK(!klass->IsLoaded());
    if (!LoadSuperAndInterfaces(klass, *new_dex_file)) {
        // Loading failed.
        if (!klass->IsErroneous()) {
            mirror::Class::SetStatus(klass, mirror::Class::kStatusErrorUnresolved, self);
        }
        return nullptr;
    }
    CHECK(klass->IsLoaded());

    // At this point the class is loaded. Publish a ClassLoad event.
    // Note: this may be a temporary class. It is a listener's responsibility to handle this.
    Runtime::Current()->GetRuntimeCallbacks()->ClassLoad(klass);

    // Link the class (if necessary)
    CHECK(!klass->IsResolved());
    // TODO: Use fast jobjects?
    auto interfaces = hs.NewHandle<mirror::ObjectArray<mirror::Class>>(nullptr);

    MutableHandle<mirror::Class> h_new_class = hs.NewHandle<mirror::Class>(nullptr);
    if (!LinkClass(self, descriptor, klass, interfaces, &h_new_class)) {
        // Linking failed.
        if (!klass->IsErroneous()) {
            mirror::Class::SetStatus(klass, mirror::Class::kStatusErrorUnresolved, self);
        }
        return nullptr;
    }
    self->AssertNoPendingException();
    CHECK(h_new_class != nullptr) << descriptor;
    CHECK(h_new_class->IsResolved() && !h_new_class->IsErroneousResolved()) << descriptor;

    // Instrumentation may have updated entrypoints for all methods of all
    // classes. However it could not update methods of this class while we
    // were loading it. Now the class is resolved, we can update entrypoints
    // as required by instrumentation.
    if (Runtime::Current()->GetInstrumentation()->AreExitStubsInstalled()) {
        // We must be in the kRunnable state to prevent instrumentation from
        // suspending all threads to update entrypoints while we are doing it
        // for this class.
        DCHECK_EQ(self->GetState(), kRunnable);
        Runtime::Current()->GetInstrumentation()->InstallStubsForClass(h_new_class.Get());
    }

    /*
    * We send CLASS_PREPARE events to the debugger from here.  The
    * definition of "preparation" is creating the static fields for a
    * class and initializing them to the standard default values, but not
    * executing any code (that comes later, during "initialization").
    *
    * We did the static preparation in LinkClass.
    *
    * The class has been prepared and resolved but possibly not yet verified
    * at this point.
    */
    Runtime::Current()->GetRuntimeCallbacks()->ClassPrepare(klass, h_new_class);

    // Notify native debugger of the new class and its layout.
    jit::Jit::NewTypeLoadedIfUsingJit(h_new_class.Get());

    return h_new_class.Get();
}
```