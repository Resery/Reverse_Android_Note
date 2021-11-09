# 1 代壳的实现原理以及脱壳点

## 前言

安卓加载器部分的源码分析主要是为了后面脱一二代壳来进行服务的，所以这篇文章会结合源码来找出 Dalvik 和 Art 下可用于脱 1 代壳的脱壳点。

## 1 代壳实现原理

第一代壳会对 dex 进行加密，使得静态分析工具没有办法解析 dex 文件，在运行时其会对 dex 进行解密，解密之后再进行运行，而我们脱壳的思路在于解密之后将其解密出来的 dex 文件 dump 下来。

## Dalvik 可用脱壳点

这里主要利用之前的源码分析来寻找可利用的脱壳点，所谓的脱壳点其实就是源码中直接或间接使用了 dex 的位置和长度的代码，因为有了这两个量我们就可以直接将这段区域的内容 dump 下来。

通过之前的源码分析可以知道 Dalvik 后面会调用一个 native 层的函数来处理 dex 文件。其实在这个函数内我们就可以进行脱壳了。

### Dalvik_dalvik_system_DexFile_defineClassNative 内进行脱壳

Dalvik_dalvik_system_DexFile_defineClassNative 函数的代码如下，可以看到他的参数在后面会被解析出来，分别解析出来一个 sourceNameObj 和一个 outputNameObj ，在这里我们就可以进行脱壳了，直接调用 open 系统调用返回一个 fd ，返回之后利用 stat 结构体获取到 dex 的文件大小，之后直接将得到的两个值作为 write 的参数，然后 write 到一个我们指定的地方。但是在这里脱壳并不一定能保证 100% 可以脱下来，因为可能壳并没有在这里对 dex 进行解密，所以我们脱下来的可能还是加密的。

```C++
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

    ...

    sourceName = dvmCreateCstrFromString(sourceNameObj);
    if (outputNameObj != NULL)
        outputName = dvmCreateCstrFromString(outputNameObj);
    else
        outputName = NULL;

    if (dvmClassPathContains(gDvm.bootClassPath, sourceName)) {
        ALOGW("Refusing to reopen boot DEX '%s'", sourceName);
        dvmThrowIOException(
            "Re-opening BOOTCLASSPATH DEX files is not allowed");
        free(sourceName);
        free(outputName);
        RETURN_VOID();
    }

    if (hasDexExtension(sourceName)
            && dvmRawDexFileOpen(sourceName, outputName, &pRawDexFile, false) == 0) {
        ALOGV("Opening DEX file '%s' (DEX)", sourceName);

        ...
    }

    ...

}
```

### dvmRawDexFileOpen 内进行脱壳

在 Dalvik_dalvik_system_DexFile_defineClassNative 源码中可以看到针对 dex 文件其会调用 dvmRawDexFileOpen 来打开 dex 文件。dvmRawDexFileOpen 参数中同样也包含 dex 文件的名字，并且在函数内部就直接 open 了这个 dex 同时也获取到了它的大小，所以在这里也可以直接进行脱壳。其中调用的 dexOptGenerateCacheFileName 函数同样也可用于脱壳其原理与在 Dalvik_dalvik_system_DexFile_defineClassNative 中进行脱壳的原理相同，即利用文件名和 stat 获取到位置和大小来脱壳。

```C++
int dvmRawDexFileOpen(const char* fileName, const char* odexOutputName,
    RawDexFile** ppRawDexFile, bool isBootstrap)
{
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

    if (verifyMagicAndGetAdler32(dexFd, &adler32) < 0) {
        ALOGE("Error with header for %s", fileName);
        goto bail;
    }

    if (getModTimeAndSize(dexFd, &modTime, &fileSize) < 0) {
        ALOGE("Error with stat for %s", fileName);
        goto bail;
    }

    if (odexOutputName == NULL) {
        cachedName = dexOptGenerateCacheFileName(fileName, NULL);
        if (cachedName == NULL)
            goto bail;
    } else {
        cachedName = strdup(odexOutputName);
    }

    optFd = dvmOpenCachedDexFile(fileName, cachedName, modTime,
        adler32, isBootstrap, &newFile, /*createIfMissing=*/true);

    if (newFile) {
        u8 startWhen, copyWhen, endWhen;
        bool result;
        off_t dexOffset;

        dexOffset = lseek(optFd, 0, SEEK_CUR);
        result = (dexOffset > 0);

        ...

        if (result) {
            result = dvmOptimizeDexFile(optFd, dexOffset, fileSize,
                fileName, modTime, adler32, isBootstrap);
        }
    }

    if (dvmDexFileOpenFromFd(optFd, &pDvmDex) != 0) {
        ALOGI("Unable to map cached %s", fileName);
        goto bail;
    }

    ...
}
```

### dvmOptimizeDexFile 内进行脱壳

dvmRawDexFileOpen 会调用 dvmOptimizeDexFile 来优化 dex 文件，在其内部会 fork 出一个子进程然后去调用内部的 opt 组件，在这里我们同样有 dex 文件的 fd 和 dexLength ，所以这里也可用于脱壳

```C++
bool dvmOptimizeDexFile(int fd, off_t dexOffset, long dexLength,
    const char* fileName, u4 modWhen, u4 crc, bool isBootstrap)
{
    ...

    pid = fork();
    if (pid == 0) {

        ...

        if (kUseValgrind)
            execv(kValgrinder, const_cast<char**>(argv));
        else
            execv(execFile, const_cast<char**>(argv));

        ...
    }

    ...
}
```

### fromDex 内进行脱壳

在这个函数里会对 dvmOptimizeDexFile 调用时传递的参数进行一个解析，解析完成之后调用 dvmContinueOptimization 进入优化的主逻辑，但是到这里的时候就已经有了 dex 文件的相关信息如 fd 和文件大小等信息，所以同样可以用来脱壳。

```C++
static int fromDex(int argc, char* const argv[])
{
    int result = -1;
    bool vmStarted = false;
    char* bootClassPath = NULL;
    int fd, flags, vmBuildVersion;
    long offset, length;
    const char* debugFileName;
    u4 crc, modWhen;
    char* endp;
    bool onlyOptVerifiedDex = false;
    DexClassVerifyMode verifyMode;
    DexOptimizerMode dexOptMode;

    ...

    /* do the optimization */
    if (!dvmContinueOptimization(fd, offset, length, debugFileName,
            modWhen, crc, (flags & DEXOPT_IS_BOOTSTRAP) != 0))
    {
        ALOGE("Optimization failed");
        goto bail;
    }
}
```

### dvmContinueOptimization 内进行脱壳

这里直接看它的参数了，参数中非常明显的 fd 和 dexOffset ，所以这个函数也可以作为脱壳点，然后在这个函数里面会调用 rewriteDex 来生成 odex 文件。

```C++
bool dvmContinueOptimization(int fd, off_t dexOffset, long dexLength,
            const char* fileName, u4 modWhen, u4 crc, bool isBootstrap) {

    ...

    {
        bool success;
        void* mapAddr;
        mapAddr = mmap(NULL, dexOffset + dexLength, PROT_READ|PROT_WRITE,
                    MAP_SHARED, fd, 0);
        if (mapAddr == MAP_FAILED) {
            ALOGE("unable to mmap DEX cache: %s", strerror(errno));
            goto bail;
        }

        ...

        success = rewriteDex(((u1*) mapAddr) + dexOffset, dexLength,
                    doVerify, doOpt, &pClassLookup, NULL);

        ...
    }

}
```

### rewriteDex 内进行脱壳

rewriteDex 同样参数中就已经包含了 addr 和 len 参数，所以同样也可以作为脱壳点，然后在这里面调用 verifyAndOptimizeClasses 来对类进行优化。

```C++
static bool rewriteDex(u1* addr, int len, bool doVerify, bool doOpt,
    DexClassLookup** ppClassLookup, DvmDex** ppDvmDex)
{

    ...

    verifyAndOptimizeClasses(pDvmDex->pDexFile, doVerify, doOpt);

    ...
}
```

### verifyAndOptimzeClasses 内进行脱壳

在 verifyAndOptimizeClasses 中参数 pDexFile 中是会存储与 dex 文件有关的信息，所以利用 pDexFile 同样也可以找到文件的起始地址和大小。这里也就同样可以用于脱壳了。

```C++
static void verifyAndOptimizeClasses(DexFile* pDexFile, bool doVerify,
    bool doOpt)
{
    u4 count = pDexFile->pHeader->classDefsSize;
    u4 idx;

    for (idx = 0; idx < count; idx++) {
        const DexClassDef* pClassDef;
        const char* classDescriptor;
        ClassObject* clazz;

        pClassDef = dexGetClassDef(pDexFile, idx);
        classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

        /* all classes are loaded into the bootstrap class loader */
        clazz = dvmLookupClass(classDescriptor, NULL, false);
        if (clazz != NULL) {
            verifyAndOptimizeClass(pDexFile, clazz, pClassDef, doVerify, doOpt);

        } else {
            // TODO: log when in verbose mode
            ALOGV("DexOpt: not optimizing unavailable class '%s'",
                classDescriptor);
        }
    }

    ...
}
```

### dvmDexFileOpenFromFd 内进行脱壳

这个函数会在优化完成之后调用，也是用来打开优化后的 odex 文件，这里同样会有 odex 文件的 fd ，并且后面还会根据这个 fd 将存储在内存中的 dex 文件的地址和长度解析出来，然后调用 dexFileParse 来对这个 odex 文件进行解析。

```C++
int dvmDexFileOpenFromFd(int fd, DvmDex** ppDvmDex)
{
    DvmDex* pDvmDex;
    DexFile* pDexFile;
    MemMapping memMap;
    int parseFlags = kDexParseDefault;
    int result = -1;

    if (gDvm.verifyDexChecksum)
        parseFlags |= kDexParseVerifyChecksum;

    if (lseek(fd, 0, SEEK_SET) < 0) {
        ALOGE("lseek rewind failed");
        goto bail;
    }

    if (sysMapFileInShmemWritableReadOnly(fd, &memMap) != 0) {
        ALOGE("Unable to map file");
        goto bail;
    }

    pDexFile = dexFileParse((u1*)memMap.addr, memMap.length, parseFlags);
    if (pDexFile == NULL) {
        ALOGE("DEX parse failed");
        sysReleaseShmem(&memMap);
        goto bail;
    }

    pDvmDex = allocateAuxStructures(pDexFile);
    if (pDvmDex == NULL) {
        dexFileFree(pDexFile);
        sysReleaseShmem(&memMap);
        goto bail;
    }

    /* tuck this into the DexFile so it gets released later */
    sysCopyMap(&pDvmDex->memMap, &memMap);
    pDvmDex->isMappedReadOnly = true;
    *ppDvmDex = pDvmDex;
    result = 0;

bail:
    return result;
}
```

### dexFileParse 内进行脱壳

dexFileParse 直接传入 data 和 length ，所以利用这两个参数就可以进行脱壳，在这里他还调用了 dexParseOptData 和 dexFileSetupBasicPointers 函数，这两个函数都传入了 pDexFile 参数，该参数的类型为 DexFile ，DexFile 中会存储与这个 Dex 文件相关的内容，所以这两个函数也可用于脱壳。

```C++
DexFile* dexFileParse(const u1* data, size_t length, int flags)
{
    DexFile* pDexFile = NULL;
    const DexHeader* pHeader;
    const u1* magic;
    int result = -1;

    ...

    pDexFile = (DexFile*) malloc(sizeof(DexFile));

    if (memcmp(data, DEX_OPT_MAGIC, 4) == 0) {
        magic = data;
        if (memcmp(magic+4, DEX_OPT_MAGIC_VERS, 4) != 0) {
            ALOGE("bad opt version (0x%02x %02x %02x %02x)",
                 magic[4], magic[5], magic[6], magic[7]);
            goto bail;
        }

        pDexFile->pOptHeader = (const DexOptHeader*) data;
        ALOGV("Good opt header, DEX offset is %d, flags=0x%02x",
            pDexFile->pOptHeader->dexOffset, pDexFile->pOptHeader->flags);

        /* parse the optimized dex file tables */
        if (!dexParseOptData(data, length, pDexFile))
            goto bail;

        /* ignore the opt header and appended data from here on out */
        data += pDexFile->pOptHeader->dexOffset;
        length -= pDexFile->pOptHeader->dexOffset;
        if (pDexFile->pOptHeader->dexLength > length) {
            ALOGE("File truncated? stored len=%d, rem len=%d",
                pDexFile->pOptHeader->dexLength, (int) length);
            goto bail;
        }
        length = pDexFile->pOptHeader->dexLength;
    }

    dexFileSetupBasicPointers(pDexFile, data);
    pHeader = pDexFile->pHeader;

    ...
}
```

### dexParseOptData 内进行脱壳

dexParseOptData 中传入的参数中包含 DexFile 类型的 pDexFile ，利用该参数可以获得到 odex 文件的起始位置和文件大小，所以可以利用此处进行脱壳。

```C++
bool dexParseOptData(const u1* data, size_t length, DexFile* pDexFile)
{
    const void* pOptStart = data + pDexFile->pOptHeader->optOffset;
    const void* pOptEnd = data + length;
    const u4* pOpt = (const u4*) pOptStart;
    u4 optLength = (const u1*) pOptEnd - (const u1*) pOptStart;

    /*
     * Make sure the opt data start is in range and aligned. This may
     * seem like a superfluous check, but (a) if the file got
     * truncated, it might turn out that pOpt >= pOptEnd; and (b)
     * if the opt data header got corrupted, pOpt might not be
     * properly aligned. This test will catch both of these cases.
     */
    if (!isValidPointer(pOpt, pOptStart, pOptEnd)) {
        ALOGE("Bogus opt data start pointer");
        return false;
    }

    /* Make sure that the opt data length is a whole number of words. */
    if ((optLength & 3) != 0) {
        ALOGE("Unaligned opt data area end");
        return false;
    }

    /*
     * Make sure that the opt data area is large enough to have at least
     * one chunk header.
     */
    if (optLength < 8) {
        ALOGE("Undersized opt data area (%u)", optLength);
        return false;
    }

    /* Process chunks until we see the end marker. */
    while (*pOpt != kDexChunkEnd) {
        if (!isValidPointer(pOpt + 2, pOptStart, pOptEnd)) {
            ALOGE("Bogus opt data content pointer at offset %u",
                    ((const u1*) pOpt) - data);
            return false;
        }

        u4 size = *(pOpt + 1);
        const u1* pOptData = (const u1*) (pOpt + 2);

        /*
         * The rounded size is 64-bit aligned and includes +8 for the
         * type/size header (which was extracted immediately above).
         */
        u4 roundedSize = (size + 8 + 7) & ~7;
        const u4* pNextOpt = pOpt + (roundedSize / sizeof(u4));

        if (!isValidPointer(pNextOpt, pOptStart, pOptEnd)) {
            ALOGE("Opt data area problem for chunk of size %u at offset %u",
                    size, ((const u1*) pOpt) - data);
            return false;
        }

        switch (*pOpt) {
        case kDexChunkClassLookup:
            pDexFile->pClassLookup = (const DexClassLookup*) pOptData;
            break;
        case kDexChunkRegisterMaps:
            ALOGV("+++ found register maps, size=%u", size);
            pDexFile->pRegisterMapPool = pOptData;
            break;
        default:
            ALOGI("Unknown chunk 0x%08x (%c%c%c%c), size=%d in opt data area",
                *pOpt,
                (char) ((*pOpt) >> 24), (char) ((*pOpt) >> 16),
                (char) ((*pOpt) >> 8),  (char)  (*pOpt),
                size);
            break;
        }

        pOpt = pNextOpt;
    }

    return true;
}
```

### dexFileSetupBasicPointers 内进行脱壳

dexFileSetupBasicPointer 中使用了 DexFile 这个结构体利用这个结构体也可实现脱壳。

```C++
void dexFileSetupBasicPointers(DexFile* pDexFile, const u1* data) {
    DexHeader *pHeader = (DexHeader*) data;

    pDexFile->baseAddr = data;
    pDexFile->pHeader = pHeader;
    pDexFile->pStringIds = (const DexStringId*) (data + pHeader->stringIdsOff);
    pDexFile->pTypeIds = (const DexTypeId*) (data + pHeader->typeIdsOff);
    pDexFile->pFieldIds = (const DexFieldId*) (data + pHeader->fieldIdsOff);
    pDexFile->pMethodIds = (const DexMethodId*) (data + pHeader->methodIdsOff);
    pDexFile->pProtoIds = (const DexProtoId*) (data + pHeader->protoIdsOff);
    pDexFile->pClassDefs = (const DexClassDef*) (data + pHeader->classDefsOff);
    pDexFile->pLinkData = (const DexLink*) (data + pHeader->linkOff);
}
```

### 小总结

上面介绍过的脱壳点原理其实都是一样的，但是并不能保证所有的脱壳点都能脱掉壳，针对不同的壳可能有效果的脱壳点都是不一样的。


## Art 可用脱壳点

Art 部分的脱壳点主要分为两部分一部分是原有的加载器部分的脱壳点，另一部分是在新加点 InMemoryDexClassLoader 中的脱壳点。

### CreateSingleDexFileCookie 内进行脱壳

CreateSingleDexFileCookie 中会创建一个 dex_file 指针，该指针指向一个 DexFile 对象，通过这个指针我们就可以获得 dex 文件的相关信息，所以这可以用作脱壳。

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

### CreateDexFile 内进行脱壳

CreateDexFile 中同样也会创建一个 dex_file 指针，指针指向的类型为 DexFile ，通过这个指针也可完成脱壳。

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

### DexFile::Open(const std::string& location, ... , std::string* error_msg) 内进行脱壳

Open 中会调用 OpenCommon 返回一个只想 DexFile 类型的指针，利用该指针可以完成脱壳。

```C++
std::unique_ptr<const DexFile> DexFile::Open(const std::string& location,
                                             uint32_t location_checksum,
                                             std::unique_ptr<MemMap> map,
                                             bool verify,
                                             bool verify_checksum,
                                             std::string* error_msg) {
  ScopedTrace trace(std::string("Open dex file from mapped-memory ") + location);
  CHECK(map.get() != nullptr);

  if (map->Size() < sizeof(DexFile::Header)) {
    *error_msg = StringPrintf(
        "DexFile: failed to open dex file '%s' that is too short to have a header",
        location.c_str());
    return nullptr;
  }

  std::unique_ptr<DexFile> dex_file = OpenCommon(map->Begin(),
                                                 map->Size(),
                                                 location,
                                                 location_checksum,
                                                 kNoOatDexFile,
                                                 verify,
                                                 verify_checksum,
                                                 error_msg);
  if (dex_file != nullptr) {
    dex_file->mem_map_.reset(map.release());
  }
  return dex_file;
}
```

### OpenCommon 内进行脱壳

OpenCommon 中也会创建一个指向 DexFile 类型的指针，利用该指针即可完成脱壳。

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

### DexFile::DexFile 内进行脱壳

DexFile 的构造函数中将与 dex 文件有关的内容全部都加载了进来，所以在构造函数这里也可以完成脱壳。

```C++
DexFile::DexFile(const uint8_t* base,
                 size_t size,
                 const std::string& location,
                 uint32_t location_checksum,
                 const OatDexFile* oat_dex_file)
    : begin_(base),
      size_(size),
      location_(location),
      location_checksum_(location_checksum),
      header_(reinterpret_cast<const Header*>(base)),
      string_ids_(reinterpret_cast<const StringId*>(base + header_->string_ids_off_)),
      type_ids_(reinterpret_cast<const TypeId*>(base + header_->type_ids_off_)),
      field_ids_(reinterpret_cast<const FieldId*>(base + header_->field_ids_off_)),
      method_ids_(reinterpret_cast<const MethodId*>(base + header_->method_ids_off_)),
      proto_ids_(reinterpret_cast<const ProtoId*>(base + header_->proto_ids_off_)),
      class_defs_(reinterpret_cast<const ClassDef*>(base + header_->class_defs_off_)),
      method_handles_(nullptr),
      num_method_handles_(0),
      call_site_ids_(nullptr),
      num_call_site_ids_(0),
      oat_dex_file_(oat_dex_file) {
  CHECK(begin_ != nullptr) << GetLocation();
  CHECK_GT(size_, 0U) << GetLocation();
  // Check base (=header) alignment.
  // Must be 4-byte aligned to avoid undefined behavior when accessing
  // any of the sections via a pointer.
  CHECK_ALIGNED(begin_, alignof(Header));

  InitializeSectionsFromMapList();
}
```



### DexFile::Open(const char* filename, ... , std::vector<std::unique_ptr<const DexFile>>* dex_files) 内进行脱壳

DexFile::Open 的另一个版本会创建一个指向 DexFile 类型的指针，利用该指针可以进行脱壳，但是想利用到这个 Open 就必须将 dex2oat 禁用掉。

```C++
bool DexFile::Open(const char* filename,
                   const std::string& location,
                   bool verify_checksum,
                   std::string* error_msg,
                   std::vector<std::unique_ptr<const DexFile>>* dex_files) {
  ScopedTrace trace(std::string("Open dex file ") + std::string(location));
  DCHECK(dex_files != nullptr) << "DexFile::Open: out-param is nullptr";
  uint32_t magic;
  File fd = OpenAndReadMagic(filename, &magic, error_msg);
  if (fd.Fd() == -1) {
    DCHECK(!error_msg->empty());
    return false;
  }
  if (IsZipMagic(magic)) {
    return DexFile::OpenZip(fd.Release(), location, verify_checksum, error_msg, dex_files);
  }
  if (IsDexMagic(magic)) {
    std::unique_ptr<const DexFile> dex_file(DexFile::OpenFile(fd.Release(),
                                                              location,
                                                              /* verify */ true,
                                                              verify_checksum,
                                                              error_msg));
    if (dex_file.get() != nullptr) {
      dex_files->push_back(std::move(dex_file));
      return true;
    } else {
      return false;
    }
  }
  *error_msg = StringPrintf("Expected valid zip or dex file: '%s'", filename);
  return false;
}
```

### OpenAndReadMagic 内进行脱壳

在 DexFile::Open(const char* filename, ... , std::vector<std::unique_ptr<const DexFile>>* dex_files) 这个版本中会调用 OpenAndReadMagic 函数，这个函数会创建一个 fd ，利用这个 fd 可以获取到 dex 文件的大小，从而达到脱壳的目的，同样想调用到这个函数也需要将 dex2oat 关闭掉。

```C++
File OpenAndReadMagic(const char* filename, uint32_t* magic, std::string* error_msg) {
  CHECK(magic != nullptr);
  File fd(filename, O_RDONLY, /* check_usage */ false);
  if (fd.Fd() == -1) {
    *error_msg = StringPrintf("Unable to open '%s' : %s", filename, strerror(errno));
    return File();
  }
  int n = TEMP_FAILURE_RETRY(read(fd.Fd(), magic, sizeof(*magic)));
  if (n != sizeof(*magic)) {
    *error_msg = StringPrintf("Failed to find magic in '%s'", filename);
    return File();
  }
  if (lseek(fd.Fd(), 0, SEEK_SET) != 0) {
    *error_msg = StringPrintf("Failed to seek to beginning of file '%s' : %s", filename,
                              strerror(errno));
    return File();
  }
  return fd;
}
```

### 小总结

Art 中的脱壳点与 Dalvik 中的脱壳点会有一些区别，其中重载的函数会比 Dalvik 多，并且两个虚拟机实现的原理不同，Art 中 dex2oat 对脱壳也会有一些影响，但是一些加固厂商会将 dex2oat 部分给禁用掉。