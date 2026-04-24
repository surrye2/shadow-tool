#!/usr/bin/env bash

# --- AlZill Advanced Cleanup Utility ---

# حدد المجلد الذي تخرج فيه النتائج عادةً لتجنب حذف ملفات الكود المصدري
RESULTS_DIR="./results"
LOGS_DIR="./logs"

echo "==============================================="
echo "🗑️  AlZill Deep Cleaner"
echo "==============================================="

# وظيفة للبحث والحذف بناءً على الصيغة مع استثناء ملف payloads.txt
cleanup_extension() {
    ext=$1
    # إحصاء الملفات قبل الحذف (مع استثناء payloads.txt للملفات النصية)
    if [ "$ext" == "txt" ]; then
        count=$(find . -type f -name "*.$ext" ! -name "payloads.txt" | wc -l)
    else
        count=$(find . -type f -name "*.$ext" | wc -l)
    fi
    
    if [ "$count" -gt 0 ]; then
        echo "[*] Found $count files with (.$ext) extension."
        # عملية الحذف مع الاستثناء
        if [ "$ext" == "txt" ]; then
            find . -type f -name "*.$ext" ! -name "payloads.txt" -delete
            echo "   ✅ Deleted all .$ext files (except payloads.txt)."
        else
            find . -type f -name "*.$ext" -delete
            echo "   ✅ Deleted all .$ext files."
        fi
    else
        echo "   ✨ No .$ext files found (or only payloads.txt exists)."
    fi
}

echo "⚠️  WARNING: This will clear all scan logs (json, txt, js results)."
echo "-----------------------------------------------"
read -p "❓ Do you want to proceed? (y/n): " confirm

if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then

    # تنفيذ الحذف للصيغ الثلاث
    cleanup_extension "json"
    cleanup_extension "txt"   # لن يتم حذف payloads.txt
    cleanup_extension "js"
    cleanup_extension "log"

    echo "-----------------------------------------------"
    echo "Done! Your workspace is now clean (payloads.txt preserved)."
else
    echo "❎ Cleanup canceled."
fi
