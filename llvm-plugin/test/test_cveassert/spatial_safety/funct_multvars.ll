; ModuleID = 'funct_multvars.c'
source_filename = "funct_multvars.c"
target datalayout = "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128"
target triple = "x86_64-pc-linux-gnu"

@.str = private unnamed_addr constant [4 x i8] c"%d \00", align 1, !dbg !0
@__const.main.arr = private unnamed_addr constant [3 x i32] [i32 0, i32 1, i32 2], align 4
@__const.main.b = private unnamed_addr constant [3 x i32] [i32 3, i32 4, i32 5], align 4

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @increment_arr(ptr noundef %0, i32 noundef %1) #0 !dbg !17 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  call void @llvm.dbg.declare(metadata ptr %3, metadata !23, metadata !DIExpression()), !dbg !24
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !25, metadata !DIExpression()), !dbg !26
  call void @llvm.dbg.declare(metadata ptr %5, metadata !27, metadata !DIExpression()), !dbg !28
  %6 = load ptr, ptr %3, align 8, !dbg !29
  store ptr %6, ptr %5, align 8, !dbg !28
  br label %7, !dbg !30

7:                                                ; preds = %14, %2
  %8 = load ptr, ptr %5, align 8, !dbg !31
  %9 = load ptr, ptr %3, align 8, !dbg !32
  %10 = load i32, ptr %4, align 4, !dbg !33
  %11 = sext i32 %10 to i64, !dbg !34
  %12 = getelementptr inbounds i32, ptr %9, i64 %11, !dbg !34
  %13 = icmp ult ptr %8, %12, !dbg !35
  br i1 %13, label %14, label %20, !dbg !30

14:                                               ; preds = %7
  %15 = load ptr, ptr %5, align 8, !dbg !36
  %16 = load i32, ptr %15, align 4, !dbg !38
  %17 = add nsw i32 %16, 1, !dbg !38
  store i32 %17, ptr %15, align 4, !dbg !38
  %18 = load ptr, ptr %5, align 8, !dbg !39
  %19 = getelementptr inbounds i32, ptr %18, i32 1, !dbg !39
  store ptr %19, ptr %5, align 8, !dbg !39
  br label %7, !dbg !30, !llvm.loop !40

20:                                               ; preds = %7
  ret void, !dbg !43
}

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: noinline nounwind optnone uwtable
define dso_local void @print_arr(ptr noundef %0, i32 noundef %1) #0 !dbg !44 {
  %3 = alloca ptr, align 8
  %4 = alloca i32, align 4
  %5 = alloca ptr, align 8
  store ptr %0, ptr %3, align 8
  call void @llvm.dbg.declare(metadata ptr %3, metadata !45, metadata !DIExpression()), !dbg !46
  store i32 %1, ptr %4, align 4
  call void @llvm.dbg.declare(metadata ptr %4, metadata !47, metadata !DIExpression()), !dbg !48
  call void @llvm.dbg.declare(metadata ptr %5, metadata !49, metadata !DIExpression()), !dbg !50
  %6 = load ptr, ptr %3, align 8, !dbg !51
  store ptr %6, ptr %5, align 8, !dbg !50
  br label %7, !dbg !52

7:                                                ; preds = %14, %2
  %8 = load ptr, ptr %5, align 8, !dbg !53
  %9 = load ptr, ptr %3, align 8, !dbg !54
  %10 = load i32, ptr %4, align 4, !dbg !55
  %11 = sext i32 %10 to i64, !dbg !56
  %12 = getelementptr inbounds i32, ptr %9, i64 %11, !dbg !56
  %13 = icmp ult ptr %8, %12, !dbg !57
  br i1 %13, label %14, label %20, !dbg !52

14:                                               ; preds = %7
  %15 = load ptr, ptr %5, align 8, !dbg !58
  %16 = load i32, ptr %15, align 4, !dbg !60
  %17 = call i32 (ptr, ...) @printf(ptr noundef @.str, i32 noundef %16), !dbg !61
  %18 = load ptr, ptr %5, align 8, !dbg !62
  %19 = getelementptr inbounds i32, ptr %18, i32 1, !dbg !62
  store ptr %19, ptr %5, align 8, !dbg !62
  br label %7, !dbg !52, !llvm.loop !63

20:                                               ; preds = %7
  ret void, !dbg !65
}

declare i32 @printf(ptr noundef, ...) #2

; Function Attrs: noinline nounwind optnone uwtable
define dso_local i32 @main() #0 !dbg !66 {
  %1 = alloca i32, align 4
  %2 = alloca [3 x i32], align 4
  %3 = alloca [3 x i32], align 4
  %4 = alloca i32, align 4
  %5 = alloca i32, align 4
  store i32 0, ptr %1, align 4
  call void @llvm.dbg.declare(metadata ptr %2, metadata !69, metadata !DIExpression()), !dbg !73
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %2, ptr align 4 @__const.main.arr, i64 12, i1 false), !dbg !73
  call void @llvm.dbg.declare(metadata ptr %3, metadata !74, metadata !DIExpression()), !dbg !75
  call void @llvm.memcpy.p0.p0.i64(ptr align 4 %3, ptr align 4 @__const.main.b, i64 12, i1 false), !dbg !75
  call void @llvm.dbg.declare(metadata ptr %4, metadata !76, metadata !DIExpression()), !dbg !77
  store i32 3, ptr %4, align 4, !dbg !77
  call void @llvm.dbg.declare(metadata ptr %5, metadata !78, metadata !DIExpression()), !dbg !79
  store i32 3, ptr %5, align 4, !dbg !79
  %6 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 0, !dbg !80
  %7 = load i32, ptr %4, align 4, !dbg !81
  call void @increment_arr(ptr noundef %6, i32 noundef %7), !dbg !82
  %8 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 0, !dbg !83
  %9 = load i32, ptr %4, align 4, !dbg !84
  call void @print_arr(ptr noundef %8, i32 noundef %9), !dbg !85
  %10 = getelementptr inbounds [3 x i32], ptr %3, i64 0, i64 0, !dbg !86
  %11 = load i32, ptr %5, align 4, !dbg !87
  call void @increment_arr(ptr noundef %10, i32 noundef %11), !dbg !88
  %12 = getelementptr inbounds [3 x i32], ptr %3, i64 0, i64 0, !dbg !89
  %13 = load i32, ptr %5, align 4, !dbg !90
  call void @print_arr(ptr noundef %12, i32 noundef %13), !dbg !91
  %14 = getelementptr inbounds [3 x i32], ptr %2, i64 0, i64 3, !dbg !92
  %15 = call i32 @resolve_sanitize_bounds_ld_i32(ptr %2, ptr %14), !dbg !92
  ret i32 %15, !dbg !93
}

; Function Attrs: nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

define internal i32 @resolve_sanitize_bounds_ld_i32(ptr %0, ptr %1) {
  %3 = call i1 @resolve_check_bounds(ptr %0, ptr %1)
  br i1 %3, label %5, label %4

4:                                                ; preds = %2
  ret void

5:                                                ; preds = %2
  %6 = load i32, ptr %1, align 4
  ret i32 %6
}

declare i1 @resolve_check_bounds(ptr, ptr)

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
attributes #2 = { "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" "target-cpu"="x86-64" "target-features"="+cmov,+cx8,+fxsr,+mmx,+sse,+sse2,+x87" "tune-cpu"="generic" }
attributes #3 = { nocallback nofree nounwind willreturn memory(argmem: readwrite) }

!llvm.dbg.cu = !{!7}
!llvm.module.flags = !{!9, !10, !11, !12, !13, !14, !15}
!llvm.ident = !{!16}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(scope: null, file: !2, line: 15, type: !3, isLocal: true, isDefinition: true)
!2 = !DIFile(filename: "funct_multvars.c", directory: "/opt/resolve/llvm-ir/test_cveassert/spatial_safety", checksumkind: CSK_MD5, checksum: "026b93d3119afc7fcb240cbfc2c11b0b")
!3 = !DICompositeType(tag: DW_TAG_array_type, baseType: !4, size: 32, elements: !5)
!4 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!5 = !{!6}
!6 = !DISubrange(count: 4)
!7 = distinct !DICompileUnit(language: DW_LANG_C11, file: !2, producer: "Ubuntu clang version 18.1.3 (1ubuntu1)", isOptimized: false, runtimeVersion: 0, emissionKind: FullDebug, globals: !8, splitDebugInlining: false, nameTableKind: None)
!8 = !{!0}
!9 = !{i32 7, !"Dwarf Version", i32 5}
!10 = !{i32 2, !"Debug Info Version", i32 3}
!11 = !{i32 1, !"wchar_size", i32 4}
!12 = !{i32 8, !"PIC Level", i32 2}
!13 = !{i32 7, !"PIE Level", i32 2}
!14 = !{i32 7, !"uwtable", i32 2}
!15 = !{i32 7, !"frame-pointer", i32 2}
!16 = !{!"Ubuntu clang version 18.1.3 (1ubuntu1)"}
!17 = distinct !DISubprogram(name: "increment_arr", scope: !2, file: !2, line: 4, type: !18, scopeLine: 4, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !22)
!18 = !DISubroutineType(types: !19)
!19 = !{null, !20, !21}
!20 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !21, size: 64)
!21 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!22 = !{}
!23 = !DILocalVariable(name: "a", arg: 1, scope: !17, file: !2, line: 4, type: !20)
!24 = !DILocation(line: 4, column: 25, scope: !17)
!25 = !DILocalVariable(name: "size", arg: 2, scope: !17, file: !2, line: 4, type: !21)
!26 = !DILocation(line: 4, column: 32, scope: !17)
!27 = !DILocalVariable(name: "ptr", scope: !17, file: !2, line: 5, type: !20)
!28 = !DILocation(line: 5, column: 10, scope: !17)
!29 = !DILocation(line: 5, column: 16, scope: !17)
!30 = !DILocation(line: 6, column: 5, scope: !17)
!31 = !DILocation(line: 6, column: 12, scope: !17)
!32 = !DILocation(line: 6, column: 18, scope: !17)
!33 = !DILocation(line: 6, column: 22, scope: !17)
!34 = !DILocation(line: 6, column: 20, scope: !17)
!35 = !DILocation(line: 6, column: 16, scope: !17)
!36 = !DILocation(line: 7, column: 10, scope: !37)
!37 = distinct !DILexicalBlock(scope: !17, file: !2, line: 6, column: 28)
!38 = !DILocation(line: 7, column: 14, scope: !37)
!39 = !DILocation(line: 8, column: 12, scope: !37)
!40 = distinct !{!40, !30, !41, !42}
!41 = !DILocation(line: 9, column: 5, scope: !17)
!42 = !{!"llvm.loop.mustprogress"}
!43 = !DILocation(line: 10, column: 1, scope: !17)
!44 = distinct !DISubprogram(name: "print_arr", scope: !2, file: !2, line: 12, type: !18, scopeLine: 12, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !22)
!45 = !DILocalVariable(name: "arr", arg: 1, scope: !44, file: !2, line: 12, type: !20)
!46 = !DILocation(line: 12, column: 21, scope: !44)
!47 = !DILocalVariable(name: "size", arg: 2, scope: !44, file: !2, line: 12, type: !21)
!48 = !DILocation(line: 12, column: 30, scope: !44)
!49 = !DILocalVariable(name: "ptr", scope: !44, file: !2, line: 13, type: !20)
!50 = !DILocation(line: 13, column: 10, scope: !44)
!51 = !DILocation(line: 13, column: 16, scope: !44)
!52 = !DILocation(line: 14, column: 5, scope: !44)
!53 = !DILocation(line: 14, column: 12, scope: !44)
!54 = !DILocation(line: 14, column: 18, scope: !44)
!55 = !DILocation(line: 14, column: 24, scope: !44)
!56 = !DILocation(line: 14, column: 22, scope: !44)
!57 = !DILocation(line: 14, column: 16, scope: !44)
!58 = !DILocation(line: 15, column: 24, scope: !59)
!59 = distinct !DILexicalBlock(scope: !44, file: !2, line: 14, column: 30)
!60 = !DILocation(line: 15, column: 23, scope: !59)
!61 = !DILocation(line: 15, column: 9, scope: !59)
!62 = !DILocation(line: 16, column: 12, scope: !59)
!63 = distinct !{!63, !52, !64, !42}
!64 = !DILocation(line: 17, column: 5, scope: !44)
!65 = !DILocation(line: 18, column: 1, scope: !44)
!66 = distinct !DISubprogram(name: "main", scope: !2, file: !2, line: 20, type: !67, scopeLine: 20, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition, unit: !7, retainedNodes: !22)
!67 = !DISubroutineType(types: !68)
!68 = !{!21}
!69 = !DILocalVariable(name: "arr", scope: !66, file: !2, line: 21, type: !70)
!70 = !DICompositeType(tag: DW_TAG_array_type, baseType: !21, size: 96, elements: !71)
!71 = !{!72}
!72 = !DISubrange(count: 3)
!73 = !DILocation(line: 21, column: 9, scope: !66)
!74 = !DILocalVariable(name: "b", scope: !66, file: !2, line: 22, type: !70)
!75 = !DILocation(line: 22, column: 9, scope: !66)
!76 = !DILocalVariable(name: "size_arr", scope: !66, file: !2, line: 24, type: !21)
!77 = !DILocation(line: 24, column: 9, scope: !66)
!78 = !DILocalVariable(name: "size_b", scope: !66, file: !2, line: 25, type: !21)
!79 = !DILocation(line: 25, column: 9, scope: !66)
!80 = !DILocation(line: 27, column: 19, scope: !66)
!81 = !DILocation(line: 27, column: 24, scope: !66)
!82 = !DILocation(line: 27, column: 5, scope: !66)
!83 = !DILocation(line: 28, column: 15, scope: !66)
!84 = !DILocation(line: 28, column: 20, scope: !66)
!85 = !DILocation(line: 28, column: 5, scope: !66)
!86 = !DILocation(line: 30, column: 19, scope: !66)
!87 = !DILocation(line: 30, column: 22, scope: !66)
!88 = !DILocation(line: 30, column: 5, scope: !66)
!89 = !DILocation(line: 31, column: 15, scope: !66)
!90 = !DILocation(line: 31, column: 18, scope: !66)
!91 = !DILocation(line: 31, column: 5, scope: !66)
!92 = !DILocation(line: 33, column: 12, scope: !66)
!93 = !DILocation(line: 33, column: 5, scope: !66)
