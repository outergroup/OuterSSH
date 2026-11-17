#ifndef OT_NULLABILITY_H
#define OT_NULLABILITY_H

/* Nullability describes pointer contracts without changing their representation. */
#if defined(__clang__)
#define OT_NULLABLE _Nullable
#define OT_NONNULL _Nonnull
#define OT_ASSUME_NONNULL_BEGIN _Pragma("clang assume_nonnull begin")
#define OT_ASSUME_NONNULL_END _Pragma("clang assume_nonnull end")
#else
#define OT_NULLABLE
#define OT_NONNULL
#define OT_ASSUME_NONNULL_BEGIN
#define OT_ASSUME_NONNULL_END
#endif

#endif
