; ModuleID = 'oob_multvars.c'
source_filename = "oob_multvars.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@__const.main.a = private unnamed_addr constant [3 x i32] [i32 0, i32 1, i32 2], align 4
@__const.main.b = private unnamed_addr constant [3 x i32] [i32 4, i32 5, i32 6], align 4
@__const.main.arr = private unnamed_addr constant [2 x i32] [i32 4, i32 5], align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @foo(ptr noundef %0, ptr noundef %1) #0 !dbg !12 {
  %3 = alloca i32, align 4
  %4 = alloca ptr, align 8
  %5 = alloca ptr, align 8
  %6 = alloca ptr, align 8
  %7 = alloca ptr, align 8
  store ptr %0, ptr %4, align 8
  call void @llvm.dbg.declare(metadata ptr %4, metadata !18, metadata !DIExpression()), !dbg !19
  store ptr %1, ptr %5, align 8
  call void @llvm.dbg.declare(metadata ptr %5, metadata !20, metadata !DIExpression()), !dbg !21
  call void @llvm.dbg.declare(metadata ptr %6, metadata !22, metadata !DIExpression()), !dbg !24
  %8 = load ptr, ptr %4, align 8, !dbg !25
  store ptr %8, ptr %6, align 8, !dbg !24
  br label %9, !dbg !26

9:                                                ; preds = %37, %2
  %10 = load ptr, ptr %6, align 8, !dbg !27
  %11 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %10), !dbg !29
  %12 = sext i32 %11 to i64, !dbg !29
  %13 = inttoptr i64 %12 to ptr, !dbg !29
  %14 = icmp ne ptr %13, null, !dbg !30
  br i1 %14, label %15, label %40, !dbg !31

15:                                               ; preds = %9
  call void @llvm.dbg.declare(metadata ptr %7, metadata !32, metadata !DIExpression()), !dbg !35
  %16 = load ptr, ptr %5, align 8, !dbg !36
  store ptr %16, ptr %7, align 8, !dbg !35
  br label %17, !dbg !37

17:                                               ; preds = %33, %15
  %18 = load ptr, ptr %7, align 8, !dbg !38
  %19 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %1, ptr %18), !dbg !40
  %20 = sext i32 %19 to i64, !dbg !40
  %21 = inttoptr i64 %20 to ptr, !dbg !40
  %22 = icmp ne ptr %21, null, !dbg !41
  br i1 %22, label %23, label %36, !dbg !42

23:                                               ; preds = %17
  %24 = load ptr, ptr %6, align 8, !dbg !43
  %25 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %24), !dbg !46
  %26 = load ptr, ptr %7, align 8, !dbg !47
  %27 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %1, ptr %26), !dbg !48
  %28 = icmp eq i32 %25, %27, !dbg !49
  br i1 %28, label %29, label %32, !dbg !50

29:                                               ; preds = %23
  %30 = load ptr, ptr %6, align 8, !dbg !51
  %31 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %30), !dbg !53
  store i32 %31, ptr %3, align 4, !dbg !54
  br label %40, !dbg !54

32:                                               ; preds = %23
  br label %33, !dbg !55

33:                                               ; preds = %32
  %34 = load ptr, ptr %7, align 8, !dbg !56
  %35 = getelementptr inbounds i32, ptr %34, i32 1, !dbg !56
  store ptr %35, ptr %7, align 8, !dbg !56
  br label %17, !dbg !57, !llvm.loop !58

36:                                               ; preds = %17
  br label %37, !dbg !61

37:                                               ; preds = %36
  %38 = load ptr, ptr %6, align 8, !dbg !62
  %39 = getelementptr inbounds i32, ptr %38, i32 1, !dbg !62
  store ptr %39, ptr %6, align 8, !dbg !62
  br label %9, !dbg !63, !llvm.loop !64

40:                                               ; preds = %29, %9
  %41 = load i32, ptr %3, align 4, !dbg !66
  ret i32 %41, !dbg !66
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !67 {
  %1 = alloca i32, align 4
  %2 = alloca [3 x i32], align 4
  %3 = alloca [3 x i32], align 4
  %4 = alloca [2 x i32], align 4
  %5 = alloca i32, align 4
  %6 = alloca i32, align 4
  %7 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !70, metadata !DIExpression()), !dbg !74
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %2, ptr align 4 @__const.main.a, i64 12, i1 false), !dbg !74
  call void @llvm.dbg.declare(metadata ptr %3, metadata !75, metadata !DIExpression()), !dbg !76
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %3, ptr align 4 @__const.main.b, i64 12, i1 false), !dbg !76
  call void @llvm.dbg.declare(metadata ptr %4, metadata !77, metadata !DIExpression()), !dbg !81
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %4, ptr align 4 @__const.main.arr, i64 8, i1 false), !dbg !81
  call void @llvm.dbg.declare(metadata ptr %5, metadata !82, metadata !DIExpression()), !dbg !83
  %8 = getelementptr inbounds [2 x i32], ptr %4, i64 0, i64 3, !dbg !84
  %9 = load i32, ptr %8, align 4, !dbg !84
  store i32 %9, ptr %5, align 4, !dbg !83
  call void @llvm.dbg.declare(metadata ptr %6, metadata !85, metadata !DIExpression()), !dbg !86
  store i32 7, ptr %6, align 4, !dbg !86
  %10 = load i32, ptr %6, align 4, !dbg !87
  %11 = getelementptr inbounds [3 x i32], ptr %3, i64 0, i64 3, !dbg !88
  store i32 %10, ptr %11, align 4, !dbg !89
  call void @llvm.dbg.declare(metadata ptr %7, metadata !90, metadata !DIExpression()), !dbg !91
  %12 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 0, !dbg !92
  %13 = getelementptr inbounds [3 x i32], ptr %3, i64 0, i64 0, !dbg !93
  %14 = call i32 @foo(ptr noundef %12, ptr noundef %13), !dbg !94
  store i32 %14, ptr %7, align 4, !dbg !91
  %15 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 3, !dbg !95
  %16 = load i32, ptr %15, align 4, !dbg !95
  ret i32 %16, !dbg !96
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #2

define internal ptr @resolve_sanitize_bounds_ld_ptr(ptr %0, ptr %1) {
  %3 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %3, label %5, label %4

4:                                                ; preds = %2
  ret ptr null

5:                                                ; preds = %2
  %6 = load ptr, ptr %1, align 8
  ret ptr %6
}

declare i1 @resolve_check_bounds(ptr, ptr)

define internal i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %1) {
  %3 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %3, label %5, label %4

4:                                                ; preds = %2
  ret ptr null

5:                                                ; preds = %2
  %6 = load i32, ptr %1, align 4
  ret i32 %6
}

define internal void @resolve_sanitize_bounds_st_ptr(ptr %0, ptr %1, ptr %2) {
  %4 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %4, label %6, label %5

5:                                                ; preds = %3
  ret void

6:                                                ; preds = %3
  store ptr %2, ptr %1, align 8
  ret void
}

define internal void @resolve_sanitize_bounds_st_i32(ptr %0, ptr %1, i32 %2) {
  %4 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %4, label %6, label %5

5:                                                ; preds = %3
  ret void

6:                                                ; preds = %3
  store i32 %2, ptr %1, align 4
  ret void
}

attributes #0 = { noinline nounwind optnone uwtable "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #1 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #2 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!0}
!llvm.module.flags = !{!4, !5, !6, !7, !8, !9, !10}
!llvm.ident = !{!11}

!0 = distinct !DICompileUnit(language: DW_LANG_C11, file: !1, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, retainedTypes: !2, splitDebugInlining: false, nameTableKind: None)
!1 = !DIFile(filename: "oob_multvars.c", directory: "/opt/resolve/llvm-ir/test_cveassert/spatial_safety", checksumkind: CSK_MD5, checksum: "bb0d36236dc785350ae03b5e81e4d841")
!2 = !{!3}
!3 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!4 = !{i32 7, !"Dwarf Version", i32 5}
!5 = !{i32 2, !"Debug Info Version", i32 3}
!6 = !{i32 1, !"wchar_size", i32 4}
!7 = !{i32 8, !"PIC Level", i32 2}
!8 = !{i32 7, !"PIE Level", i32 2}
!9 = !{i32 7, !"uwtable", i32 2}
!10 = !{i32 7, !"frame-pointer", i32 2}
!11 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!12 = distinct !DISubprogram(name: "foo", scope: !1, file: !1, line: 12, type: !13, scopeLine: 12, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !17)
!13 = !DISubroutineType(types: !14)
!14 = !{!15, !16, !16}
!15 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!16 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !15, size: 64)
!17 = !{}
!18 = !DILocalVariable(name: "arr1", arg: 1, scope: !12, file: !1, line: 12, type: !16)
!19 = !DILocation(line: 12, column: 14, scope: !12)
!20 = !DILocalVariable(name: "arr2", arg: 2, scope: !12, file: !1, line: 12, type: !16)
!21 = !DILocation(line: 12, column: 25, scope: !12)
!22 = !DILocalVariable(name: "ptr1", scope: !23, file: !1, line: 13, type: !16)
!23 = distinct !DILexicalBlock(scope: !12, file: !1, line: 13, column: 5)
!24 = !DILocation(line: 13, column: 14, scope: !23)
!25 = !DILocation(line: 13, column: 21, scope: !23)
!26 = !DILocation(line: 13, column: 9, scope: !23)
!27 = !DILocation(line: 13, column: 28, scope: !28)
!28 = distinct !DILexicalBlock(scope: !23, file: !1, line: 13, column: 5)
!29 = !DILocation(line: 13, column: 27, scope: !28)
!30 = !DILocation(line: 13, column: 33, scope: !28)
!31 = !DILocation(line: 13, column: 5, scope: !23)
!32 = !DILocalVariable(name: "ptr2", scope: !33, file: !1, line: 14, type: !16)
!33 = distinct !DILexicalBlock(scope: !34, file: !1, line: 14, column: 9)
!34 = distinct !DILexicalBlock(scope: !28, file: !1, line: 13, column: 50)
!35 = !DILocation(line: 14, column: 18, scope: !33)
!36 = !DILocation(line: 14, column: 25, scope: !33)
!37 = !DILocation(line: 14, column: 13, scope: !33)
!38 = !DILocation(line: 14, column: 32, scope: !39)
!39 = distinct !DILexicalBlock(scope: !33, file: !1, line: 14, column: 9)
!40 = !DILocation(line: 14, column: 31, scope: !39)
!41 = !DILocation(line: 14, column: 37, scope: !39)
!42 = !DILocation(line: 14, column: 9, scope: !33)
!43 = !DILocation(line: 15, column: 18, scope: !44)
!44 = distinct !DILexicalBlock(scope: !45, file: !1, line: 15, column: 17)
!45 = distinct !DILexicalBlock(scope: !39, file: !1, line: 14, column: 54)
!46 = !DILocation(line: 15, column: 17, scope: !44)
!47 = !DILocation(line: 15, column: 27, scope: !44)
!48 = !DILocation(line: 15, column: 26, scope: !44)
!49 = !DILocation(line: 15, column: 23, scope: !44)
!50 = !DILocation(line: 15, column: 17, scope: !45)
!51 = !DILocation(line: 16, column: 25, scope: !52)
!52 = distinct !DILexicalBlock(scope: !44, file: !1, line: 15, column: 33)
!53 = !DILocation(line: 16, column: 24, scope: !52)
!54 = !DILocation(line: 16, column: 17, scope: !52)
!55 = !DILocation(line: 18, column: 9, scope: !45)
!56 = !DILocation(line: 14, column: 50, scope: !39)
!57 = !DILocation(line: 14, column: 9, scope: !39)
!58 = distinct !{!58, !42, !59, !60}
!59 = !DILocation(line: 18, column: 9, scope: !33)
!60 = !{!"llvm.loop.mustprogress"}
!61 = !DILocation(line: 19, column: 5, scope: !34)
!62 = !DILocation(line: 13, column: 46, scope: !28)
!63 = !DILocation(line: 13, column: 5, scope: !28)
!64 = distinct !{!64, !31, !65, !60}
!65 = !DILocation(line: 19, column: 5, scope: !23)
!66 = !DILocation(line: 20, column: 1, scope: !12)
!67 = distinct !DISubprogram(name: "main", scope: !1, file: !1, line: 22, type: !68, scopeLine: 22, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !0, retainedNodes: !17)
!68 = !DISubroutineType(types: !69)
!69 = !{!15}
!70 = !DILocalVariable(name: "a", scope: !67, file: !1, line: 23, type: !71)
!71 = !DICompositeType(tag: DW_TAG_array_type, baseType: !15, size: 96, elements: !72)
!72 = !{!73}
!73 = !DISubrange(count: 3)
!74 = !DILocation(line: 23, column: 9, scope: !67)
!75 = !DILocalVariable(name: "b", scope: !67, file: !1, line: 24, type: !71)
!76 = !DILocation(line: 24, column: 9, scope: !67)
!77 = !DILocalVariable(name: "arr", scope: !67, file: !1, line: 25, type: !78)
!78 = !DICompositeType(tag: DW_TAG_array_type, baseType: !15, size: 64, elements: !79)
!79 = !{!80}
!80 = !DISubrange(count: 2)
!81 = !DILocation(line: 25, column: 9, scope: !67)
!82 = !DILocalVariable(name: "x", scope: !67, file: !1, line: 26, type: !15)
!83 = !DILocation(line: 26, column: 9, scope: !67)
!84 = !DILocation(line: 26, column: 13, scope: !67)
!85 = !DILocalVariable(name: "y", scope: !67, file: !1, line: 27, type: !15)
!86 = !DILocation(line: 27, column: 9, scope: !67)
!87 = !DILocation(line: 28, column: 12, scope: !67)
!88 = !DILocation(line: 28, column: 5, scope: !67)
!89 = !DILocation(line: 28, column: 10, scope: !67)
!90 = !DILocalVariable(name: "res", scope: !67, file: !1, line: 30, type: !15)
!91 = !DILocation(line: 30, column: 9, scope: !67)
!92 = !DILocation(line: 30, column: 19, scope: !67)
!93 = !DILocation(line: 30, column: 22, scope: !67)
!94 = !DILocation(line: 30, column: 15, scope: !67)
!95 = !DILocation(line: 32, column: 12, scope: !67)
!96 = !DILocation(line: 32, column: 5, scope: !67)
