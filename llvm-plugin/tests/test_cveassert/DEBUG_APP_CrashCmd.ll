define internal i8 @resolve_sanitize_null_ptr_ld_i8(ptr %0) {
  %2 = icmp eq ptr %0, null
  br i1 %2, label %3, label %4

3:                                                ; preds = %1
  ret i8 0

4:                                                ; preds = %1
  %5 = load i8, ptr %0, align 1
  ret i8 %5
}
define internal ptr @resolve_sanitize_null_ptr_ld_ptr(ptr %0) {
  %2 = icmp eq ptr %0, null
  br i1 %2, label %3, label %4

3:                                                ; preds = %1
  ret ptr null

4:                                                ; preds = %1
  %5 = load ptr, ptr %0, align 8
  ret ptr %5
}
define internal void @resolve_sanitize_null_ptr_st_ptr(ptr %0, ptr %1) {
  %3 = icmp eq ptr %0, null
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  ret void

5:                                                ; preds = %2
  store ptr %1, ptr %0, align 8
  ret void
}
define internal void @resolve_sanitize_null_ptr_st_i8(ptr %0, i8 %1) {
  %3 = icmp eq ptr %0, null
  br i1 %3, label %4, label %5

4:                                                ; preds = %2
  ret void

5:                                                ; preds = %2
  store i8 %1, ptr %0, align 1
  ret void
}

@DEBUG_APP_Data = unnamed_addr global i8 0

; Function Attrs: nounwind uwtable
define i32 @DEBUG_APP_CrashCmdUnsafe(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  store ptr %0, ptr %2, align 8
  %4 = load i8, ptr @DEBUG_APP_Data, align 4
  %5 = add i8 %4, 1
  store i8 %5, ptr @DEBUG_APP_Data, align 4
  call void @llvm.lifetime.start.p0(i64 8, ptr %3) #3
  store ptr null, ptr %3, align 8
  %7 = load ptr, ptr %3, align 8
  %8 = getelementptr inbounds i8, ptr %7, i64 0
  store i8 97, ptr %8, align 1
  call void @llvm.lifetime.end.p0(i64 8, ptr %3) #3
  ret i32 0
}

; Function Attrs: nounwind uwtable
define i32 @DEBUG_APP_CrashCmd(ptr noundef %0) #0 {
  %2 = alloca ptr, align 8
  %3 = alloca ptr, align 8
  call void @resolve_sanitize_null_ptr_st_ptr(ptr %2, ptr %0)
  %4 = call i8 @resolve_sanitize_null_ptr_ld_i8(ptr @DEBUG_APP_Data)
  %5 = add i8 %4, 1
  call void @resolve_sanitize_null_ptr_st_i8(ptr @DEBUG_APP_Data, i8 %5)
  call void @llvm.lifetime.start.p0(i64 8, ptr %3) #3
  call void @resolve_sanitize_null_ptr_st_ptr(ptr %3, ptr null)
  %7 = call ptr @resolve_sanitize_null_ptr_ld_ptr(ptr %3)
  %8 = getelementptr inbounds i8, ptr %7, i64 0
  call void @resolve_sanitize_null_ptr_st_i8(ptr %8, i8 97)
  call void @llvm.lifetime.end.p0(i64 8, ptr %3) #3
  ret i32 0
}
