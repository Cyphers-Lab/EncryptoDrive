#include "fusefs.hpp"
#include <fuse3/fuse.h>
#include <mutex>
#include <thread>
#include <sys/statfs.h>
#include <cstring>
#include <fcntl.h>

namespace encrypto::fs {

namespace {

// Get filesystem instance from FUSE context
FileSystem* get_fs() {
    struct fuse_context* context = fuse_get_context();
    return static_cast<FileSystem*>(context->private_data);
}

// FUSE operation implementations
int fs_getattr(const char* path, struct stat* stbuf, struct fuse_file_info*) {
    auto fs = get_fs();
    auto metadata = fs->getMetadata(path);
    
    if (!metadata) {
        return -ENOENT;
    }

    memset(stbuf, 0, sizeof(struct stat));
    
    if (fs::is_directory(metadata->path)) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
    } else {
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
        stbuf->st_size = metadata->size;
    }

    // Convert file_time_type to time_t via duration since epoch
    auto duration = metadata->modified.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    time_t tp = static_cast<time_t>(seconds);
    stbuf->st_mtime = tp;
    
    return 0;
}

int fs_readdir(const char* path, void* buf, fuse_fill_dir_t filler,
               [[maybe_unused]] off_t offset, struct fuse_file_info*, 
               enum fuse_readdir_flags) {
    auto fs = get_fs();
    auto entries = fs->listDirectory(path);

    filler(buf, ".", nullptr, 0, FUSE_FILL_DIR_PLUS);
    filler(buf, "..", nullptr, 0, FUSE_FILL_DIR_PLUS);

    for (const auto& entry : entries) {
        filler(buf, entry.filename().c_str(), nullptr, 0, FUSE_FILL_DIR_PLUS);
    }

    return 0;
}

int fs_open(const char* path, struct fuse_file_info* fi) {
    auto fs = get_fs();
    auto metadata = fs->getMetadata(path);
    
    if (!metadata) {
        return -ENOENT;
    }

    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        return 0;
    }

    return -EACCES;
}

int fs_read(const char* path, char* buf, size_t size, off_t offset,
            struct fuse_file_info*) {
    auto fs = get_fs();
    auto data = fs->readFile(path);
    
    if (data.empty()) {
        return -ENOENT;
    }

    if (offset >= static_cast<off_t>(data.size())) {
        return 0;
    }

    size_t len = std::min(size, data.size() - offset);
    memcpy(buf, data.data() + offset, len);
    
    return len;
}

int fs_write(const char* path, const char* buf, size_t size,
             off_t offset, struct fuse_file_info*) {
    auto fs = get_fs();
    auto data = fs->readFile(path);
    
    if (offset > static_cast<off_t>(data.size())) {
        return -EFBIG;
    }

    // Resize buffer if needed
    if (offset + size > data.size()) {
        data.resize(offset + size);
    }

    // Write data at offset
    memcpy(data.data() + offset, buf, size);

    auto result = fs->writeFile(path, data);
    if (!result.success) {
        return -EIO;
    }

    return size;
}

int fs_create(const char* path, mode_t, struct fuse_file_info*) {
    auto fs = get_fs();
    auto result = fs->writeFile(path, {});
    
    return result.success ? 0 : -EIO;
}

int fs_unlink(const char* path) {
    auto fs = get_fs();
    auto result = fs->deleteFile(path);
    
    return result.success ? 0 : -ENOENT;
}

int fs_mkdir(const char* path, mode_t) {
    if (fs::create_directory(path)) {
        return 0;
    }
    return -EEXIST;
}

int fs_rmdir(const char* path) {
    if (fs::remove(path)) {
        return 0;
    }
    return -ENOENT;
}

int fs_statfs(const char*, struct statvfs* stbuf) {
    memset(stbuf, 0, sizeof(struct statvfs));
    stbuf->f_namemax = 255;
    stbuf->f_bsize = 4096;
    return 0;
}

} // namespace

class FuseFilesystem::Impl {
public:
    explicit Impl(std::shared_ptr<FileSystem> fs) 
        : fs_(std::move(fs)) {
        ops_.init = nullptr;
        ops_.getattr = fs_getattr;
        ops_.readdir = fs_readdir;
        ops_.open = fs_open;
        ops_.read = fs_read;
        ops_.write = fs_write;
        ops_.create = fs_create;
        ops_.unlink = fs_unlink;
        ops_.mkdir = fs_mkdir;
        ops_.rmdir = fs_rmdir;
        ops_.statfs = fs_statfs;
    }

    bool mount(const MountOptions& options) {
        if (mounted_) {
            return false;
        }

        mount_options_ = options;

        // Prepare FUSE arguments
        std::vector<const char*> fuse_args = {
            "encrypto",
            "-f", // Run in foreground
            mount_options_.mount_point.c_str()
        };

        if (mount_options_.read_only) {
            fuse_args.push_back("-r");
        }
        
        if (mount_options_.allow_other) {
            fuse_args.push_back("-o");
            fuse_args.push_back("allow_other");
        }
        
        if (mount_options_.single_thread) {
            fuse_args.push_back("-s");
        }

        // Create FUSE instance
        struct fuse_args args = FUSE_ARGS_INIT(static_cast<int>(fuse_args.size()), 
                                             const_cast<char**>(fuse_args.data()));
        
        fuse_ = fuse_new(&args, &ops_, sizeof(ops_), fs_.get());
        if (!fuse_) {
            return false;
        }

        // Mount filesystem
        if (fuse_mount(fuse_, mount_options_.mount_point.c_str()) != 0) {
            fuse_destroy(fuse_);
            fuse_ = nullptr;
            return false;
        }

        // Start FUSE loop in background thread
        fuse_thread_ = std::thread([this]() {
            fuse_loop(fuse_);
        });

        mounted_ = true;
        return true;
    }

    bool unmount() {
        if (!mounted_) {
            return false;
        }

        // Unmount filesystem
        fuse_unmount(fuse_);
        
        // Wait for FUSE thread to finish
        if (fuse_thread_.joinable()) {
            fuse_thread_.join();
        }

        // Cleanup
        fuse_destroy(fuse_);
        fuse_ = nullptr;
        mounted_ = false;

        return true;
    }

    bool isMounted() const {
        return mounted_;
    }

    fs::path getMountPoint() const {
        return mounted_ ? mount_options_.mount_point : fs::path();
    }

private:
    std::shared_ptr<FileSystem> fs_;
    struct fuse_operations ops_ = {};
    struct fuse* fuse_ = nullptr;
    MountOptions mount_options_;
    std::thread fuse_thread_;
    bool mounted_ = false;
};

// Public interface implementation
FuseFilesystem::FuseFilesystem(std::shared_ptr<FileSystem> fs)
    : impl_(std::make_unique<Impl>(std::move(fs))) {
}

FuseFilesystem::~FuseFilesystem() {
    if (impl_->isMounted()) {
        impl_->unmount();
    }
}

bool FuseFilesystem::mount(const MountOptions& options) {
    return impl_->mount(options);
}

bool FuseFilesystem::unmount() {
    return impl_->unmount();
}

bool FuseFilesystem::isMounted() const {
    return impl_->isMounted();
}

fs::path FuseFilesystem::getMountPoint() const {
    return impl_->getMountPoint();
}

} // namespace encrypto::fs
