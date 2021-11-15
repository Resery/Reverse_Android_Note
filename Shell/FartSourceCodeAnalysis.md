# Fart 源码分析（基于主动调用的脱壳机制）

## 前言

在了解了第二代抽取壳的实现之后，发现可以用脱第二代壳的方法来脱第二代壳，但是在脱壳点把脱壳代码加上之后，虽然该脱壳点可以对部分函数进行脱取，但是并不能覆盖到所有的函数，所以出现了一种叫做主动调用的技术用来脱第二代壳。Fart 就是一种基于主动调用的脱壳工具，此篇文章分析他是如何主动调用并进行脱壳修复的。

## 实现思路

Fart 通过修改 Android 内部的源码以及反射机制来实现主动调用，主动调用之后在通用的脱壳点将函数的代码提出来，提出来之后再根据得到的一些信息进行恢复即可。

## 源码分析

FART 的入口在 frameworks\base\core\java\android\app\ActivityThread.java 的 performLaunchActivity 函数中，在 app 的 activity 启动时执行 fartthread 函数。

```java
private Activity performLaunchActivity(ActivityClientRecord r, Intent customIntent) {
    ...
    //add
	fartthread();
	//add
    ...
}
```

fartthread 会创建一个线程，并且在睡眠了一分钟之后调用 fart 函数。

```java
public static void fartthread() {
    new Thread(new Runnable() {

        @Override
        public void run() {
            try {
                Log.e("ActivityThread", "start sleep,wait for fartthread start......");
                Thread.sleep(1 * 60 * 1000);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
            Log.e("ActivityThread", "sleep over and start fartthread");
            fart();
            Log.e("ActivityThread", "fart run over");

        }
    }).start();
}
```

首先调用 getClassloader 获取一个 ClassLoader 类加载器，然后获取类加载器中的 pathList 对象，再获取 pathList 对象中的 dexElements 数组，dexElements 数组中会存储所有加载进来的 dex 文件。获取 dexElements 数组元素的 dexFile 字段，这里获取 dexFile 字段主要是用于后面反射获取 dex 文件中所有的函数。使用类加载器加载 DexFile 类，获取类中的 getClasssNameList 、 defineClassNative 和 dumpMethodCode 方法，前两个方法是 Android 源码中本来就存在的，dumpMethodCode 方法是 Fart 添加的后面会分析其功能。遍历 dexElements 数组，利用反射机制获取数组中的每一个 dexfile 对象，再获取每个 dexfile 对象的 mCookie 对象，该对象会存储 openDexFile 函数的返回值，之后利用反射调用 getClassNameList 其中前面获取的 dexfile 和 mcookie 作为调用的参数。调用结束后会获得一个类名的数组，针对数组中的每一个元素调用 loadClassAndInvoke 函数。

```java
public static void fart() {
    ClassLoader appClassloader = getClassloader();
    List<Object> dexFilesArray = new ArrayList<Object>();
    Field pathList_Field = (Field) getClassField(appClassloader, "dalvik.system.BaseDexClassLoader", "pathList");
    Object pathList_object = getFieldOjbect("dalvik.system.BaseDexClassLoader", appClassloader, "pathList");
    Object[] ElementsArray = (Object[]) getFieldOjbect("dalvik.system.DexPathList", pathList_object, "dexElements");
    Field dexFile_fileField = null;
    try {
        dexFile_fileField = (Field) getClassField(appClassloader, "dalvik.system.DexPathList$Element", "dexFile");
    } catch (Exception e) {
        e.printStackTrace();
    }
    Class DexFileClazz = null;
    try {
        DexFileClazz = appClassloader.loadClass("dalvik.system.DexFile");
    } catch (Exception e) {
        e.printStackTrace();
    }
    Method getClassNameList_method = null;
    Method defineClass_method = null;
    Method dumpDexFile_method = null;
    Method dumpMethodCode_method = null;

    for (Method field : DexFileClazz.getDeclaredMethods()) {
        if (field.getName().equals("getClassNameList")) {
            getClassNameList_method = field;
            getClassNameList_method.setAccessible(true);
        }
        if (field.getName().equals("defineClassNative")) {
            defineClass_method = field;
            defineClass_method.setAccessible(true);
        }
        if (field.getName().equals("dumpMethodCode")) {
            dumpMethodCode_method = field;
            dumpMethodCode_method.setAccessible(true);
        }
    }
    Field mCookiefield = getClassField(appClassloader, "dalvik.system.DexFile", "mCookie");
    for (int j = 0; j < ElementsArray.length; j++) {
        Object element = ElementsArray[j];
        Object dexfile = null;
        try {
            dexfile = (Object) dexFile_fileField.get(element);
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (dexfile == null) {
            continue;
        }
        if (dexfile != null) {
            dexFilesArray.add(dexfile);
            Object mcookie = getClassFieldObject(appClassloader, "dalvik.system.DexFile", dexfile, "mCookie");
            if (mcookie == null) {
                continue;
            }
            String[] classnames = null;
            try {
                classnames = (String[]) getClassNameList_method.invoke(dexfile, mcookie);
            } catch (Exception e) {
                e.printStackTrace();
                continue;
            } catch (Error e) {
                e.printStackTrace();
                continue;
            }
            if (classnames != null) {
                for (String eachclassname : classnames) {
                    loadClassAndInvoke(appClassloader, eachclassname, dumpMethodCode_method);
                }
            }

        }
    }
    return;
}
```

loadClassAndInvoke 中首先调用 loadClass 获取函数参数中 eachclassname 指定的类，利用反射机制获取类中的构造函数和声明的方法，然后调用 dumpMethodCode_method 来 dump 函数代码。

```java
public static void loadClassAndInvoke(ClassLoader appClassloader, String eachclassname, Method dumpMethodCode_method) {
    Log.i("ActivityThread", "go into loadClassAndInvoke->" + "classname:" + eachclassname);
    Class resultclass = null;
    try {
        resultclass = appClassloader.loadClass(eachclassname);
    } catch (Exception e) {
        e.printStackTrace();
        return;
    } catch (Error e) {
        e.printStackTrace();
        return;
    } 
    if (resultclass != null) {
        try {
            Constructor<?> cons[] = resultclass.getDeclaredConstructors();
            for (Constructor<?> constructor : cons) {
                if (dumpMethodCode_method != null) {
                    try {
                        dumpMethodCode_method.invoke(null, constructor);
                    } catch (Exception e) {
                        e.printStackTrace();
                        continue;
                    } catch (Error e) {
                        e.printStackTrace();
                        continue;
                    } 
                } else {
                    Log.e("ActivityThread", "dumpMethodCode_method is null ");
                }

            }
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Error e) {
            e.printStackTrace();
        } 
        try {
            Method[] methods = resultclass.getDeclaredMethods();
            if (methods != null) {
                for (Method m : methods) {
                    if (dumpMethodCode_method != null) {
                        try {
                            dumpMethodCode_method.invoke(null, m);
                            } catch (Exception e) {
                            e.printStackTrace();
                            continue;
                        } catch (Error e) {
                            e.printStackTrace();
                            continue;
                        } 
                    } else {
                        Log.e("ActivityThread", "dumpMethodCode_method is null ");
                    }
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        } catch (Error e) {
            e.printStackTrace();
        } 
    }
}
```

DexFile_dumpMethodCode 函数中将传入的反射类型的 method 转变成 ArtMethod 类型的方法，然后调用 myfartInvoke 函数。

```C++
static void DexFile_dumpMethodCode(JNIEnv* env, jclass,jobject method) {
    ScopedFastNativeObjectAccess soa(env);
    if(method!=nullptr) {
        ArtMethod* artmethod = ArtMethod::FromReflectedMethod(soa, method);
        myfartInvoke(artmethod);
    }	  

    return;
}
```

myfartInvoke 函数中初始化了几个参数，然后调用 ArtMethod 中的 Invoke 方法。

```C++
extern "C" void myfartInvoke(ArtMethod * artmethod)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
    JValue *result = nullptr;
    Thread *self = nullptr;
    uint32_t temp = 6;
    uint32_t *args = &temp;
    uint32_t args_size = 6;
    artmethod->Invoke(self, args, args_size, result, "fart");
}
```

Fart 中修改了 ArtMethod 的 Invoke 方法，如果传入的 self 参数为空则代表现在是需要我们来 dump 这个方法了，然后就调用 dumpArtMethod 函数。

```C++
void ArtMethod::Invoke(Thread * self, uint32_t * args,
                uint32_t args_size, JValue * result,
                const char *shorty) {


    if (self == nullptr) {
        dumpArtMethod(this);
        return;
    }
    ...
}
```

dumpArtMethod 会通过 artmethod 来获取 DexFile 对象，然后利用 DexFile 对象得到 dex 文件的起始地址和大小，此时就可以将 dex 文件脱下来。接着利用反射获取到 CodeItem 对象，然后计算 CodeItem 的大小，计算主要是利用 dex 文件格式相关的信息，这里分为了两种情况一种是 codeitem 中包含 try catch 结构一种是不包含，如果有的话则利用 dex 文件格式计算出 codeitem 的大小（不详细对其进行说明了），如果没有可以直接根据 codeitem 的 insns_size_in_code_units 字段计算出 codeitem 的大小。然后将这个 codeitem 填回 dex 文件中。

```C++
extern "C" void dumpArtMethod(ArtMethod * artmethod)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
    char *dexfilepath = (char *) malloc(sizeof(char) * 2000);
    if (dexfilepath == nullptr) {
        LOG(INFO) <<
            "ArtMethod::dumpArtMethodinvoked,methodname:"
            << PrettyMethod(artmethod).
            c_str() << "malloc 2000 byte failed";
        return;
    }
    int fcmdline = -1;
    char szCmdline[64] = { 0 };
    char szProcName[256] = { 0 };
    int procid = getpid();
    sprintf(szCmdline, "/proc/%d/cmdline", procid);
    fcmdline = open(szCmdline, O_RDONLY, 0644);
    if (fcmdline > 0) {
        read(fcmdline, szProcName, 256);
        close(fcmdline);
    }

    if (szProcName[0]) {

        const DexFile *dex_file = artmethod->GetDexFile();
        const char *methodname =
            PrettyMethod(artmethod).c_str();
        const uint8_t *begin_ = dex_file->Begin();
        size_t size_ = dex_file->Size();

        memset(dexfilepath, 0, 2000);
        int size_int_ = (int) size_;

        memset(dexfilepath, 0, 2000);
        sprintf(dexfilepath, "%s", "/sdcard/fart");
        mkdir(dexfilepath, 0777);

        memset(dexfilepath, 0, 2000);
        sprintf(dexfilepath, "/sdcard/fart/%s",
            szProcName);
        mkdir(dexfilepath, 0777);

        memset(dexfilepath, 0, 2000);
        sprintf(dexfilepath,
            "/sdcard/fart/%s/%d_dexfile.dex",
            szProcName, size_int_);
        int dexfilefp = open(dexfilepath, O_RDONLY, 0666);
        if (dexfilefp > 0) {
            close(dexfilefp);
            dexfilefp = 0;

        } else {
            dexfilefp =
                open(dexfilepath, O_CREAT | O_RDWR,
                    0666);
            if (dexfilefp > 0) {
                write(dexfilefp, (void *) begin_,
                        size_);
                fsync(dexfilefp);
                close(dexfilefp);
            }


        }
        const DexFile::CodeItem * code_item =
            artmethod->GetCodeItem();
        if (LIKELY(code_item != nullptr)) {
            int code_item_len = 0;
            uint8_t *item = (uint8_t *) code_item;
            if (code_item->tries_size_ > 0) {
                const uint8_t *handler_data =
                    (const uint8_t *) (DexFile::
                                GetTryItems
                                (*code_item,
                            code_item->
                            tries_size_));
                uint8_t *tail =
                    codeitem_end(&handler_data);
                code_item_len =
                    (int) (tail - item);
            } else {
                code_item_len =
                    16 +
                    code_item->
                    insns_size_in_code_units_ * 2;
            }
            memset(dexfilepath, 0, 2000);
            int size_int = (int) dex_file->Size();	// Length of data
            uint32_t method_idx =
                artmethod->get_method_idx();
            sprintf(dexfilepath,
                "/sdcard/fart/%s/%d_%ld.bin",
                szProcName, size_int, gettidv1());
            int fp2 =
                open(dexfilepath,
                    O_CREAT | O_APPEND | O_RDWR,
                    0666);
            if (fp2 > 0) {
                lseek(fp2, 0, SEEK_END);
                memset(dexfilepath, 0, 2000);
                int offset = (int) (item - begin_);
                sprintf(dexfilepath,
                    "{name:%s,method_idx:%d,offset:%d,code_item_len:%d,ins:",
                    methodname, method_idx,
                    offset, code_item_len);
                int contentlength = 0;
                while (dexfilepath[contentlength]
                        != 0)
                    contentlength++;
                write(fp2, (void *) dexfilepath,
                        contentlength);
                long outlen = 0;
                char *base64result =
                    base64_encode((char *) item,
                            (long)
                            code_item_len,
                            &outlen);
                write(fp2, base64result, outlen);
                write(fp2, "};", 2);
                fsync(fp2);
                close(fp2);
                if (base64result != nullptr) {
                    free(base64result);
                    base64result = nullptr;
                }
            }

        }


    }

    if (dexfilepath != nullptr) {
        free(dexfilepath);
        dexfilepath = nullptr;
    }

}
```

Fart 中还有一个 dumpDexFileByExecute 函数，该函数和 dumpDexFile 函数的上半部分很像会 dump 出一个 dex 文件，但是并没有看到怎么调用到这个函数，通过搜索找到在 art\runtime\interpreter\interpreter.cc 文件的开始，看到了 FART 在 art 命名空间下声明了一个 dumpDexFileByExecute 函数，并且这个函数在这个文件内也有调用点。在调用函数中，通过判断函数名称中是否存在 <clinit> 即是否为静态代码块来决定要不要调用 dumpDexFileByExecute ，如果存在则调用 dumpDexFileByExecute 函数，并传入一个 ArtMethod 指针。

```C++
extern "C" void dumpDexFileByExecute(ArtMethod * artmethod)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
    char *dexfilepath = (char *) malloc(sizeof(char) * 2000);
    if (dexfilepath == nullptr) {
        LOG(INFO) <<
            "ArtMethod::dumpDexFileByExecute,methodname:"
            << PrettyMethod(artmethod).
            c_str() << "malloc 2000 byte failed";
        return;
    }
    int fcmdline = -1;
    char szCmdline[64] = { 0 };
    char szProcName[256] = { 0 };
    int procid = getpid();
    sprintf(szCmdline, "/proc/%d/cmdline", procid);
    fcmdline = open(szCmdline, O_RDONLY, 0644);
    if (fcmdline > 0) {
        read(fcmdline, szProcName, 256);
        close(fcmdline);
    }

    if (szProcName[0]) {

        const DexFile *dex_file = artmethod->GetDexFile();
        const uint8_t *begin_ = dex_file->Begin();    // Start of data.
        size_t size_ = dex_file->Size();    // Length of data.

        memset(dexfilepath, 0, 2000);
        int size_int_ = (int) size_;

        memset(dexfilepath, 0, 2000);
        sprintf(dexfilepath, "%s", "/sdcard/fart");
        mkdir(dexfilepath, 0777);

        memset(dexfilepath, 0, 2000);
        sprintf(dexfilepath, "/sdcard/fart/%s",
            szProcName);
        mkdir(dexfilepath, 0777);

        memset(dexfilepath, 0, 2000);
        sprintf(dexfilepath,
            "/sdcard/fart/%s/%d_dexfile_execute.dex",
            szProcName, size_int_);
        int dexfilefp = open(dexfilepath, O_RDONLY, 0666);
        if (dexfilefp > 0) {
            close(dexfilefp);
            dexfilefp = 0;

        } else {
            dexfilefp =
                open(dexfilepath, O_CREAT | O_RDWR,
                    0666);
            if (dexfilefp > 0) {
                write(dexfilefp, (void *) begin_,
                        size_);
                fsync(dexfilefp);
                close(dexfilefp);
            }


        }
    }

    if (dexfilepath != nullptr) {
        free(dexfilepath);
        dexfilepath = nullptr;
    }

}
```
static inline JValue Execute(Thread* self, const DexFile::CodeItem* code_item,
                             ShadowFrame& shadow_frame, JValue result_register) { 
  if(strstr(PrettyMethod(shadow_frame.GetMethod()).c_str(),"<clinit>")!=nullptr)
  {
      dumpDexFileByExecute(shadow_frame.GetMethod());
  }
  ......
}

## 总结

分析结束后可以发现在实现上并不是特别的难，但是需要对安卓中的 JNI 和 dex 文件格式很熟悉，同时这个脱壳思路也是很值得学习的。

## 参考链接

https://www.anquanke.com/post/id/219094#h2-3