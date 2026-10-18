/* NativeActivity callbacks retain no witness, proof buffer or borrowed Rust object. */
#include <android/log.h>
#include <android/native_activity.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* Rust copies the callback's application-private directory before returning. */
extern int32_t houseki_qualification_configure(const uint8_t *directory, size_t length);

/* Foreground admission tries one configured attempt and never queues another. */
extern int32_t houseki_qualification_resume(void);

/* Cancellation is requested while the callback still has execution time. */
extern int32_t houseki_qualification_pause(void);

/* Reports only a public lifecycle result, never any synthetic witness values. */
static void resume(ANativeActivity *activity) {
    (void)activity;
    int32_t result = houseki_qualification_resume();
    __android_log_print(ANDROID_LOG_INFO, "HousekiQualification", "resume status=%d", result);
}

/* Stops admission and requests cleanup without blocking the application's main thread. */
static void pause(ANativeActivity *activity) {
    (void)activity;
    int32_t result = houseki_qualification_pause();
    __android_log_print(ANDROID_LOG_INFO, "HousekiQualification", "pause status=%d", result);
}

/* Uses the NDK's declared ABI rather than mirroring platform structure layouts in Rust. */
void ANativeActivity_onCreate(ANativeActivity *activity, void *saved, size_t saved_size) {
    (void)saved;
    (void)saved_size;
    const char *directory = activity->internalDataPath;
    int32_t result = houseki_qualification_configure((const uint8_t *)directory, strlen(directory));
    __android_log_print(ANDROID_LOG_INFO, "HousekiQualification", "configure status=%d", result);
    activity->callbacks->onResume = resume;
    activity->callbacks->onPause = pause;
    activity->callbacks->onStop = pause;
    activity->callbacks->onDestroy = pause;
}
