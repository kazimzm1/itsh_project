#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tool Decode Itsh — ملف الأداة الرئيسية."""

from __future__ import annotations
import re, base64, sys
from pathlib import Path
import sys
import os
import time
import io
from pathlib import Path

import argparse
import logging
import tempfile
import shutil
import subprocess
import zipfile

import re
import base64
import binascii
import zlib
import marshal
import dis
import ast
from typing import List, Tuple, Optional

#----------------------------------------------------------------------------------
Red_Dark = "\033[38;5;1m"
Green_Dark = "\033[38;5;2m"
Yellow_Dark = "\033[38;5;3m"
Blue_Dark = "\033[38;5;4m"
Magenta_Dark = "\033[38;5;5m"
Cyan_Dark = "\033[38;5;6m"
White_Dark = "\033[38;5;7m"
Gray_Dark = "\033[38;5;8m"
Red_Light = "\033[38;5;9m"
Green_Light = "\033[38;5;10m"
Yellow_Light = "\033[38;5;11m"
Blue_Light = "\033[38;5;12m"
Magenta_Light = "\033[38;5;13m"
Cyan_Light = "\033[38;5;14m"
White_Light = "\033[38;5;15m"
Black = "\033[38;5;16m"
Navy_Blue = "\033[38;5;17m"
Dark_Blue = "\033[38;5;18m"
Medium_Blue = "\033[38;5;19m"
Dark_Cyan = "\033[38;5;20m"
Sky_Blue_Dark = "\033[38;5;21m"
Forest_Green = "\033[38;5;22m"
Spring_Green = "\033[38;5;23m"
Turquoise = "\033[38;5;24m"
Deep_Sky_Blue = "\033[38;5;25m"
Dodger_Blue = "\033[38;5;26m"
Steel_Blue = "\033[38;5;27m"
Sea_Green = "\033[38;5;28m"
Emerald = "\033[38;5;29m"
Dark_Green = "\033[38;5;30m"
Olive_Green = "\033[38;5;31m"
Chartreuse = "\033[38;5;32m"
Lawn_Green = "\033[38;5;33m"
Lime_Green = "\033[38;5;34m"
Pale_Green = "\033[38;5;35m"
Dark_Slate_Gray = "\033[38;5;36m"
Dark_Turquoise = "\033[38;5;37m"
Cadet_Blue = "\033[38;5;38m"
Aqua = "\033[38;5;39m"
Dark_Cyan_2 = "\033[38;5;40m"
Teal = "\033[38;5;41m"
Green_Yellow = "\033[38;5;42m"
Yellow_Green = "\033[38;5;43m"
Spring_Green_2 = "\033[38;5;44m"
Turquoise_2 = "\033[38;5;45m"
Light_Sky_Blue = "\033[38;5;46m"
Royal_Blue = "\033[38;5;47m"
Medium_Slate_Blue = "\033[38;5;48m"
Light_Slate_Blue = "\033[38;5;49m"
Medium_Turquoise = "\033[38;5;50m"
Blue_Violet = "\033[38;5;51m"
Yellow_Orange = "\033[38;5;52m"
Red_Orange = "\033[38;5;53m"
Medium_Orchid = "\033[38;5;54m"
Medium_Violet_Red = "\033[38;5;55m"
Indian_Red = "\033[38;5;56m"
Light_Coral = "\033[38;5;57m"
Coral = "\033[38;5;58m"
Tomato = "\033[38;5;59m"
Orange_Red = "\033[38;5;60m"
Dark_Orange = "\033[38;5;61m"
Orange = "\033[38;5;62m"
Dark_Orange_2 = "\033[38;5;63m"
Light_Salmon = "\033[38;5;64m"
Salmon = "\033[38;5;65m"
Dark_Salmon = "\033[38;5;66m"
Light_Goldenrod_Yellow = "\033[38;5;67m"
Papaya_Whip = "\033[38;5;68m"
Moccasin = "\033[38;5;69m"
Peach_Puff = "\033[38;5;70m"
Pale_Goldenrod = "\033[38;5;71m"
Khaki = "\033[38;5;72m"
Dark_Khaki = "\033[38;5;73m"
Olive_Drab = "\033[38;5;74m"
Yellow_Olive = "\033[38;5;75m"
Beige = "\033[38;5;76m"
Light_Green = "\033[38;5;77m"
Forest_Green_2 = "\033[38;5;78m"
Sea_Green_2 = "\033[38;5;79m"
Light_Turquoise = "\033[38;5;80m"
Medium_Aquamarine = "\033[38;5;81m"
Medium_Sea_Green = "\033[38;5;82m"
Medium_Purple = "\033[38;5;83m"
Light_Purple = "\033[38;5;84m"
Lavender = "\033[38;5;85m"
Slate_Blue = "\033[38;5;86m"
Medium_Violet = "\033[38;5;87m"
Dark_Violet = "\033[38;5;88m"
Purple = "\033[38;5;89m"
Dark_Purple = "\033[38;5;90m"
Blue_Gray = "\033[38;5;91m"
Light_Sky_Blue_2 = "\033[38;5;92m"
Light_Blue = "\033[38;5;93m"
Light_Sky_Blue_3 = "\033[38;5;94m"
Deep_Sky_Blue_2 = "\033[38;5;95m"
Aqua_Marine = "\033[38;5;96m"
Powder_Blue = "\033[38;5;97m"
Light_Sea_Green = "\033[38;5;98m"
Dark_Slate_Blue = "\033[38;5;99m"
Light_Turquoise_2 = "\033[38;5;100m"
Turquoise_3 = "\033[38;5;101m"
Deep_Sky_Blue_3 = "\033[38;5;102m"
Dodger_Blue_2 = "\033[38;5;103m"
Medium_Orchid_2 = "\033[38;5;104m"
Slate_Gray_2 = "\033[38;5;105m"
Slate_Blue_2 = "\033[38;5;106m"
Steel_Blue_2 = "\033[38;5;107m"
Light_Purple_2 = "\033[38;5;108m"
Light_Cyan = "\033[38;5;109m"
Light_Coral_2 = "\033[38;5;110m"
Light_Salmon_2 = "\033[38;5;111m"
Coral_2 = "\033[38;5;112m"
Dark_Salmon_2 = "\033[38;5;113m"
Orange_2 = "\033[38;5;114m"
Tomato_2 = "\033[38;5;115m"
Orange_Red_2 = "\033[38;5;116m"
Dark_Orange_2 = "\033[38;5;117m"
Light_Sea_Green_2 = "\033[38;5;118m"
Light_Pink = "\033[38;5;119m"
Light_Yellow = "\033[38;5;120m"
Pale_Turquoise = "\033[38;5;121m"
Lime = "\033[38;5;122m"
Light_Aquamarine = "\033[38;5;123m"
Sandy_Brown = "\033[38;5;124m"
Crimson = "\033[38;5;125m"
Olive = "\033[38;5;126m"
Plum = "\033[38;5;127m"
Royal_Purple = "\033[38;5;128m"
Dark_Orange_3 = "\033[38;5;129m"
Violet = "\033[38;5;130m"
Dark_Brown = "\033[38;5;131m"
Goldenrod = "\033[38;5;132m"
Dark_Green_2 = "\033[38;5;133m"
Slate_Green = "\033[38;5;134m"
Beige_2 = "\033[38;5;135m"
Pale_Pink = "\033[38;5;136m"
Rosy_Brown = "\033[38;5;137m"
Chocolate = "\033[38;5;138m"
Firebrick = "\033[38;5;139m"
Medium_Spring_Green = "\033[38;5;140m"
Dark_Goldenrod = "\033[38;5;141m"
Tomato_3 = "\033[38;5;142m"
Dark_Violet_2 = "\033[38;5;143m"
Yellow_2 = "\033[38;5;144m"
Medium_Orchid_3 = "\033[38;5;145m"
Medium_Violet_Red_2 = "\033[38;5;146m"
Lavender_Blush = "\033[38;5;147m"
Blanched_Almond = "\033[38;5;148m"
Peach_Puff_2 = "\033[38;5;149m"
Light_Goldenrod = "\033[38;5;150m"
Khaki_2 = "\033[38;5;151m"
Light_Gray = "\033[38;5;152m"
Slate_Gray = "\033[38;5;153m"
Silver_Gray = "\033[38;5;154m"
Light_Slate_Gray = "\033[38;5;155m"
Dark_Sea_Green = "\033[38;5;156m"
Sea_Green_3 = "\033[38;5;157m"
Forest_Green_2 = "\033[38;5;158m"
Dark_Khaki_2 = "\033[38;5;159m"
Medium_Sea_Green_2 = "\033[38;5;160m"
Light_Cyan_2 = "\033[38;5;161m"
Dark_Sky_Blue = "\033[38;5;162m"
Slate_Blue_3 = "\033[38;5;163m"
Medium_Purple_2 = "\033[38;5;164m"
Goldenrod_2 = "\033[38;5;165m"
Chocolate_2 = "\033[38;5;166m"
Firebrick_2 = "\033[38;5;167m"
Red_3 = "\033[38;5;168m"
Lime_2 = "\033[38;5;169m"
Olive_Drab_2 = "\033[38;5;170m"
Dark_Green_3 = "\033[38;5;171m"
Medium_Purple_3 = "\033[38;5;172m"
Pale_Green_2 = "\033[38;5;173m"
Dark_Sea_Green_2 = "\033[38;5;174m"
Deep_Sky_Blue_3 = "\033[38;5;175m"
Royal_Blue_2 = "\033[38;5;176m"
Medium_Violet_Red_3 = "\033[38;5;177m"
Pink = "\033[38;5;178m"
Lime_Green_2 = "\033[38;5;179m"
Light_Coral_2 = "\033[38;5;180m"
Orange_2 = "\033[38;5;181m"
Tomato_4 = "\033[38;5;182m"
Light_Sky_Blue_4 = "\033[38;5;183m"
Medium_Turquoise_2 = "\033[38;5;184m"
Light_Goldenrod_2 = "\033[38;5;185m"
Goldenrod_3 = "\033[38;5;186m"
Light_Salmon_3 = "\033[38;5;187m"
Dark_Orange_4 = "\033[38;5;188m"
Yellow_Orange_2 = "\033[38;5;189m"
Pale_Violet_Red = "\033[38;5;190m"
Orange_Yellow = "\033[38;5;191m"
Crimson_2 = "\033[38;5;192m"
Dark_Orange_5 = "\033[38;5;193m"
Medium_Aquamarine_2 = "\033[38;5;194m"
Medium_Spring_Green_2 = "\033[38;5;195m"
Pink_2 = "\033[38;5;196m"
Light_Turquoise_4 = "\033[38;5;197m"
Spring_Green_3 = "\033[38;5;198m"
Light_Pink_2 = "\033[38;5;199m"
Royal_Blue_3 = "\033[38;5;200m"
Dark_Sky_Blue_2 = "\033[38;5;201m"
Light_Yellow_2 = "\033[38;5;202m"
Royal_Green = "\033[38;5;203m"
Aqua_2 = "\033[38;5;204m"
Medium_Green = "\033[38;5;205m"
Lavender_2 = "\033[38;5;206m"
Peach_2 = "\033[38;5;207m"
Light_Violet = "\033[38;5;209m"
Royal_Yellow = "\033[38;5;210m"
Light_SeaGreen = "\033[38;5;211m"
Electric_Lime = "\033[38;5;212m"
Yellow_Green = "\033[38;5;213m"
Spring_Green_4 = "\033[38;5;214m"
Pastel_Pink = "\033[38;5;215m"
Slate_Gray_2 = "\033[38;5;216m"
Green_Yellow = "\033[38;5;217m"
Orange_Yellow_2 = "\033[38;5;218m"
Dark_Goldenrod_3 = "\033[38;5;219m"
PeachPuff_3 = "\033[38;5;220m"
Goldenrod_4 = "\033[38;5;221m"
Yellow_Green_2 = "\033[38;5;222m"
Light_Coral_3 = "\033[38;5;223m"
Pink_Lavender = "\033[38;5;224m"
Dark_Orange_2 = "\033[38;5;225m"
Goldenrod_3 = "\033[38;5;226m"
Slate_Blue_4 = "\033[38;5;227m"
Plum_2 = "\033[38;5;228m"
Purple_2 = "\033[38;5;229m"
Medium_Turquoise_3 = "\033[38;5;230m"
Blue_Violet_2 = "\033[38;5;231m"
Medium_Turquoise = "\033[38;5;232m"
Medium_Purple_3 = "\033[38;5;233m"
Deep_Sky_Blue_2 = "\033[38;5;234m"
Lime_Green_3 = "\033[38;5;235m"
Medium_SeaGreen_2 = "\033[38;5;236m"
Light_Blue_2 = "\033[38;5;237m"
Aquamarine_3 = "\033[38;5;238m"
Medium_Aquamarine = "\033[38;5;239m"
Deep_Pink_3 = "\033[38;5;240m"
Light_Yellow_3 = "\033[38;5;241m"
Dark_Violet = "\033[38;5;242m"
Lavender_3 = "\033[38;5;243m"
Peach_4 = "\033[38;5;244m"
Lime_2 = "\033[38;5;245m"
Forest_Green_3 = "\033[38;5;246m"
Medium_Spring_Green_3 = "\033[38;5;247m"
SeaGreen_3 = "\033[38;5;248m"
Blue_3 = "\033[38;5;249m"
Aquamarine_4 = "\033[38;5;250m"
Turquoise = "\033[38;5;251m"
Light_SeaGreen_2 = "\033[38;5;252m"
Medium_Violet_Red_4 = "\033[38;5;253m"
Lavender_Blush_2 = "\033[38;5;254m"
Pink_3 = "\033[38;5;255m"
Royal_Blue_2 = "\033[38;5;256m"
Forest_Green_4 = "\033[38;5;257m"
Chartreuse_2 = "\033[38;5;258m"
Firebrick_3 = "\033[38;5;259m"
Dark_Sky_Blue_4 = "\033[38;5;260m"
Orange_3 = "\033[38;5;261m"
Pale_Violet_Red_2 = "\033[38;5;262m"
Medium_SeaGreen_3 = "\033[38;5;263m"
Light_SeaGreen_3 = "\033[38;5;264m"
Magenta_3 = "\033[38;5;265m"
Red_Violet_2 = "\033[38;5;266m"
Dark_Orange_2 = "\033[38;5;267m"
Green_Yellow_3 = "\033[38;5;268m"
SeaGreen_4 = "\033[38;5;269m"
Orange_4 = "\033[38;5;270m"
Orange_3 = "\033[38;5;271m"
Yellow_2 = "\033[38;5;272m"
Turquoise_2 = "\033[38;5;273m"
Medium_Aquamarine_2 = "\033[38;5;274m"
Dark_Khaki_3 = "\033[38;5;275m"
Light_Pink_3 = "\033[38;5;276m"
Goldenrod_2 = "\033[38;5;277m"
Royal_Blue_3 = "\033[38;5;278m"
SeaGreen_2 = "\033[38;5;279m"
Medium_Green_2 = "\033[38;5;280m"
Blue_4 = "\033[38;5;281m"
Dark_SeaGreen_3 = "\033[38;5;282m"
Purple_3 = "\033[38;5;283m"
Orange_5 = "\033[38;5;284m"
Pale_Green_2 = "\033[38;5;285m"
Plum_3 = "\033[38;5;286m"
Dark_Violet_2 = "\033[38;5;287m"
Medium_Turquoise_4 = "\033[38;5;288m"
Lavender_4 = "\033[38;5;289m"
Dark_Turquoise = "\033[38;5;290m"
Pale_Violet_Red_3 = "\033[38;5;291m"
Medium_SeaGreen_4 = "\033[38;5;292m"
Light_SkyBlue_3 = "\033[38;5;293m"
Dark_Goldenrod_4 = "\033[38;5;294m"
Firebrick_2 = "\033[38;5;295m"
Royal_Green_2 = "\033[38;5;296m"
Medium_Purple_4 = "\033[38;5;297m"
Light_Goldenrod = "\033[38;5;298m"
Slate_Gray_3 = "\033[38;5;299m"
Dark_SeaGreen_4 = "\033[38;5;300m"
Green_Lime_2 = "\033[38;5;301m"
Dark_Pink_2 = "\033[38;5;302m"
Lavender_2 = "\033[38;5;303m"
Medium_Purple_5 = "\033[38;5;328m"
Slate_Blue_5 = "\033[38;5;329m"
Dark_Turquoise_2 = "\033[38;5;330m"
Light_Pink_5 = "\033[38;5;331m"
Aqua_4 = "\033[38;5;332m"
Medium_Violet_Red_5 = "\033[38;5;333m"
Forest_Green_6 = "\033[38;5;334m"
Violet_2 = "\033[38;5;335m"
Steel_Blue_3 = "\033[38;5;336m"
Orange_6 = "\033[38;5;337m"
Slate_Gray_6 = "\033[38;5;338m"
Pale_Turquoise_2 = "\033[38;5;339m"
Lavender_5 = "\033[38;5;340m"
Light_Green_2 = "\033[38;5;341m"
Yellow_4 = "\033[38;5;342m"
Turquoise_4 = "\033[38;5;343m"
Indigo_2 = "\033[38;5;344m"
Medium_Rose = "\033[38;5;345m"
Light_Lime_2 = "\033[38;5;346m"
Pastel_Orange = "\033[38;5;347m"
SeaGreen_5 = "\033[38;5;348m"
Dark_Goldenrod_5 = "\033[38;5;349m"
Deep_Sky_Blue_4 = "\033[38;5;350m"
Light_SeaGreen_4 = "\033[38;5;351m"
Royal_Orange = "\033[38;5;352m"
Yellow_Green_4 = "\033[38;5;353m"
Turquoise_5 = "\033[38;5;354m"
Lavender_6 = "\033[38;5;355m"
Medium_Purple_6 = "\033[38;5;356m"
Light_Blue_3 = "\033[38;5;357m"
Dark_Pink_3 = "\033[38;5;358m"
Orange_7 = "\033[38;5;359m"
Forest_Green_7 = "\033[38;5;360m"
Medium_Turquoise_6 = "\033[38;5;361m"
Pale_Green_3 = "\033[38;5;362m"
Lavender_Blush_3 = "\033[38;5;363m"
Slate_Gray_7 = "\033[38;5;364m"
Pale_Turquoise_3 = "\033[38;5;365m"
Peach_2 = "\033[38;5;366m"
Medium_SeaGreen_5 = "\033[38;5;367m"
Light_Turquoise = "\033[38;5;368m"
Yellow_5 = "\033[38;5;369m"
Spring_Green_2 = "\033[38;5;370m"
Dark_Purple_2 = "\033[38;5;371m"
SeaGreen_6 = "\033[38;5;372m"
Dark_SlateBlue_2 = "\033[38;5;373m"
Purple_4 = "\033[38;5;374m"
Light_Goldenrod_2 = "\033[38;5;375m"
Coral_2 = "\033[38;5;376m"
Blue_Violet_3 = "\033[38;5;377m"
Lavender_7 = "\033[38;5;378m"
Aquamarine_5 = "\033[38;5;379m"
Slate_Gray_8 = "\033[38;5;380m"
Light_Coral_2 = "\033[38;5;381m"
Medium_Green_3 = "\033[38;5;382m"
Lime_3 = "\033[38;5;383m"
Fuchsia_3 = "\033[38;5;384m"
Deep_Pink_4 = "\033[38;5;385m"
Royal_Blue_4 = "\033[38;5;386m"
Purple_5 = "\033[38;5;387m"
Goldenrod_3 = "\033[38;5;388m"
SlateBlue_3 = "\033[38;5;389m"
SeaGreen_7 = "\033[38;5;390m"
Light_SeaGreen_5 = "\033[38;5;391m"
Medium_Turquoise_7 = "\033[38;5;392m"
Medium_Rose_2 = "\033[38;5;393m"
Dark_Goldenrod_6 = "\033[38;5;394m"
Violet_3 = "\033[38;5;395m"
Dark_Violet_3 = "\033[38;5;396m"
Forest_Green_8 = "\033[38;5;397m"
Indigo_3 = "\033[38;5;398m"
Peach_3 = "\033[38;5;399m"
Turquoise_6 = "\033[38;5;400m"
Pale_Violet_Red_2 = "\033[38;5;401m"
Light_Coral_3 = "\033[38;5;402m"
Purple_6 = "\033[38;5;403m"
Spring_Green_3 = "\033[38;5;404m"
Medium_SeaGreen_6 = "\033[38;5;405m"
Light_Turquoise_2 = "\033[38;5;406m"
Medium_Green_4 = "\033[38;5;407m"
Deep_Sky_Blue_5 = "\033[38;5;408m"
Lime_4 = "\033[38;5;409m"
Slate_Gray_9 = "\033[38;5;410m"
Aqua_Marine_2 = "\033[38;5;411m"
Light_Violet_3 = "\033[38;5;412m"
Lavender_8 = "\033[38;5;413m"
Light_Green_3 = "\033[38;5;414m"
Dark_SlateBlue_3 = "\033[38;5;415m"
Blue_5 = "\033[38;5;416m"
Orange_8 = "\033[38;5;417m"
Violet_4 = "\033[38;5;418m"
Medium_Aquamarine_3 = "\033[38;5;419m"
Royal_Blue_5 = "\033[38;5;420m"
Pink_4 = "\033[38;5;421m"
Light_SeaGreen_6 = "\033[38;5;422m"
Goldenrod_4 = "\033[38;5;423m"
Medium_Turquoise_8 = "\033[38;5;424m"
Peach_4 = "\033[38;5;425m"
Lavender_9 = "\033[38;5;426m"
Light_Yellow_3 = "\033[38;5;427m"
Coral_3 = "\033[38;5;428m"
Spring_Green_4 = "\033[38;5;429m"
Forest_Green_9 = "\033[38;5;430m"
SlateBlue_4 = "\033[38;5;431m"
Medium_Violet_Red_6 = "\033[38;5;432m"
SeaGreen_8 = "\033[38;5;433m"
Slate_Gray_10 = "\033[38;5;434m"
Aqua_Blue_2 = "\033[38;5;435m"
Light_Blue_4 = "\033[38;5;436m"
Aquamarine_6 = "\033[38;5;437m"
Blue_6 = "\033[38;5;438m"
Medium_Purple_7 = "\033[38;5;439m"
Slate_Gray_11 = "\033[38;5;440m"
Pale_Turquoise_4 = "\033[38;5;441m"
Lime_5 = "\033[38;5;442m"
Pale_Green_4 = "\033[38;5;443m"
Deep_Pink_5 = "\033[38;5;444m"
#-------------------------------------------------------------------------------------
print('-' * 60)
print('TOOL DECODE ITSH')
print('-' * 60)
import os
mint       = "\033[1;38;5;121m"  # نعناعي
rose       = "\033[1;38;5;211m"  # وردي ناعم
rest = "\033[0m" #استرجاع اللون الى الون الصلي
peach      = "\033[1;38;5;216m"  # خوخي ناعم
try:
 from cfonts import render, say
except:
    os.system('pip install render')
    os.system('pip install python-cfonts')
din = render(f'TOOL DECODE ITSH', colors=['red', 'yellow'], align='center')
a=f'''
                       {din}
'''

print(a)
os.system('clear')
print(f'Decode lamed_zlib_Base64 [1]')
print(f'Decode zlib_Base64 [2]')
print(f'Decode marshal [3]')
print(f'Decode xor_base64_key [4]')
print(f'Decode base64 [5]')
print(f'Decode zlip_base64_pro [6]')
print(f'Decode ninjapy [7]')
print(f'Decode exee(lamed___evel(lamed [8]')
print(f'Decode bz2 [9]')
print(f'Decode B__ [10]')
print(f'Decode marshal_zlib_base64 [11]')
print(f'Decode base64pro [12]')
DECODE = input(f'enter numper:      ')
if DECODE == "1":
    MAX_LAYERS = 10
    MAX_FILE_BYTES = 10 * 1024 * 1024  # تجاهل الملفات الأكبر من 10MB افتراضياً
    MIN_B64_MATCH_LEN = 80
    def try_b16_rev(data: bytes) -> Optional[bytes]:
        try:
            m = re.search(rb"b['\"]([0-9A-Fa-f]+)['\"]", data)
            if m:
                hexs = m.group(1)
            else:
                m2 = re.search(rb"([0-9A-Fa-f]{64,})", data)
                hexs = m2.group(1) if m2 else None
            if not hexs:
                return None
            rev = hexs[::-1]
            return binascii.unhexlify(rev)
        except Exception:
            return None


    def try_b16(data: bytes) -> Optional[bytes]:
        try:
            m = re.search(rb"b['\"]([0-9A-Fa-f]+)['\"]", data)
            hexs = m.group(1) if m else None
            if not hexs:
                m2 = re.search(rb"([0-9A-Fa-f]{64,})", data)
                hexs = m2.group(1) if m2 else None
            if not hexs:
                return None
            return binascii.unhexlify(hexs)
        except Exception:
            return None


    def try_base64(data: bytes) -> Optional[bytes]:
        try:
            m = re.search(rb"([A-Za-z0-9+/]{%d,}={0,2})" % MIN_B64_MATCH_LEN, data)
            if not m:
                return None
            b64 = m.group(1)
            return base64.b64decode(b64)
        except Exception:
            return None


    def try_zlib(data: bytes) -> Optional[bytes]:
        try:
            return zlib.decompress(data)
        except Exception:
            return None


    def try_marshal(data: bytes) -> Optional[Tuple[object, str]]:
        try:
            obj = marshal.loads(data)
            return obj, repr(obj)
        except Exception:
            return None


    def readable_path_for_zip(input_path: str, root_base: str) -> str:
        """
        Returns a relative path used inside the ZIP to avoid absolute paths.
        root_base is the base folder the user started from (or ''), used to keep structure sensible.
        """
        # make relative if possible
        try:
            if root_base:
                rel = os.path.relpath(input_path, root_base)
            else:
                rel = os.path.basename(input_path)
        except Exception:
            rel = os.path.basename(input_path)
        return rel.replace(os.sep, "/")


    def process_single_file_into_zip(input_path: str, ziph: zipfile.ZipFile, root_base: str = ""):
        """
        Process one file and write all outputs into the open ZipFile handle (ziph).
        All entries are created under a directory named after the input file (relative).
        """
        # safety: skip large files
        try:
            st = os.stat(input_path)
            if st.st_size > MAX_FILE_BYTES:
                msg = f"[تخطي] {input_path} ({st.st_size} bytes) — أكبر من الحد ({MAX_FILE_BYTES} bytes)."
                print(msg)
                # write a small note inside the zip explaining skip
                rel = readable_path_for_zip(input_path, root_base)
                note_name = f"{rel}/SKIPPED_size_note.txt"
                ziph.writestr(note_name, msg.encode("utf-8", errors="ignore"))
                return
        except Exception:
            pass

        try:
            with open(input_path, "rb") as f:
                original = f.read()
        except Exception as e:
            err = f"[خطأ] تعذّر قراءة الملف {input_path}: {e}"
            print(err)
            rel = readable_path_for_zip(input_path, root_base)
            ziph.writestr(f"{rel}/ERROR_reading.txt", err)
            return

        rel = readable_path_for_zip(input_path, root_base)
        report_lines = []
        saved_entries = []

        report_lines.append(f"Input file: {input_path}")
        report_lines.append(f"Size: {len(original)} bytes\n")

        # Save the original (only if not huge) as .original.txt for inspection
        try:
            ziph.writestr(f"{rel}/original.bin", original)
            saved_entries.append(f"{rel}/original.bin")
        except Exception as e:
            report_lines.append(f"تعذّر إضافة النسخة الأصلية للأرشيف: {e}")

        current = original
        layer = 0

        for i in range(MAX_LAYERS):
            layer += 1
            report_lines.append(f"\n--- محاولة طبقة {layer} ---")
            succeeded = False

            # reverse base16
            res = try_b16_rev(current)
            if res:
                report_lines.append(f"وجدت سلسلة base16 محتملة مع عكس. حجم بعد unhex: {len(res)}")
                # اختبر zlib
                z = try_zlib(res)
                if z:
                    entry_name = f"{rel}/layer{layer:02d}.reverse_base16_then_zlib.bin"
                    ziph.writestr(entry_name, z)
                    saved_entries.append(entry_name)
                    report_lines.append(f"نجح zlib -> حفظ في: {entry_name}")
                    current = z
                    succeeded = True
                    continue
                else:
                    entry_name = f"{rel}/layer{layer:02d}.reverse_base16.bin"
                    ziph.writestr(entry_name, res)
                    saved_entries.append(entry_name)
                    report_lines.append(f"حُفظت نتيجة reverse+base16: {entry_name}")
                    current = res
                    succeeded = True
                    continue

            # base16
            res = try_b16(current)
            if res:
                report_lines.append(f"وجدت base16 (بدون عكس). حجم after unhex: {len(res)}")
                z = try_zlib(res)
                if z:
                    entry_name = f"{rel}/layer{layer:02d}.base16_then_zlib.bin"
                    ziph.writestr(entry_name, z)
                    saved_entries.append(entry_name)
                    report_lines.append(f"نجح zlib -> حفظ في: {entry_name}")
                    current = z
                    succeeded = True
                    continue
                else:
                    entry_name = f"{rel}/layer{layer:02d}.base16.bin"
                    ziph.writestr(entry_name, res)
                    saved_entries.append(entry_name)
                    report_lines.append(f"حُفظت نتيجة base16: {entry_name}")
                    current = res
                    succeeded = True
                    continue

            # base64
            res = try_base64(current)
            if res:
                report_lines.append(f"وجدت base64. حجم بعد decode: {len(res)}")
                z = try_zlib(res)
                if z:
                    entry_name = f"{rel}/layer{layer:02d}.base64_then_zlib.bin"
                    ziph.writestr(entry_name, z)
                    saved_entries.append(entry_name)
                    report_lines.append(f"نجح zlib -> حفظ في: {entry_name}")
                    current = z
                    succeeded = True
                    continue
                else:
                    entry_name = f"{rel}/layer{layer:02d}.base64.bin"
                    ziph.writestr(entry_name, res)
                    saved_entries.append(entry_name)
                    report_lines.append(f"حُفظت نتيجة base64: {entry_name}")
                    current = res
                    succeeded = True
                    continue

            # zlib directly
            res = try_zlib(current)
            if res:
                entry_name = f"{rel}/layer{layer:02d}.zlib.bin"
                ziph.writestr(entry_name, res)
                saved_entries.append(entry_name)
                report_lines.append(f"نجح zlib مباشرة -> حفظ في: {entry_name} (حجم: {len(res)})")
                current = res
                succeeded = True
                continue

            # marshal.loads attempt (ثابت فقط)
            mres = try_marshal(current)
            if mres:
                obj, reprtext = mres
                report_lines.append("نجح marshal.loads على البايتات.")
                if hasattr(obj, "co_code"):
                    # disassembly text
                    sio = io.StringIO()
                    sio.write(f"# disassembly of marshal code object (layer {layer})\n")
                    try:
                        for instr in dis.Bytecode(obj):
                            sio.write(str(instr) + "\n")
                        dis_text = sio.getvalue()
                    except Exception as e:
                        dis_text = f"# فشل الحصول على disassembly: {e}\n{reprtext}\n"
                    entry_name = f"{rel}/layer{layer:02d}.marshal.dis.txt"
                    ziph.writestr(entry_name, dis_text.encode("utf-8", errors="ignore"))
                    saved_entries.append(entry_name)
                    report_lines.append(f"حُفظت disassembly: {entry_name}")
                else:
                    entry_name = f"{rel}/layer{layer:02d}.marshal_repr.txt"
                    ziph.writestr(entry_name, reprtext.encode("utf-8", errors="ignore"))
                    saved_entries.append(entry_name)
                    report_lines.append(f"حُفظ تمثيل marshal: {entry_name}")
                succeeded = True
                # لا نغيّر current دائماً بعد marshal (قد يكون تمثيلا مستقلا)
                continue

            # لا شيء اكتُشف
            report_lines.append("لم تُكتَشف أي عملية مفكوك معروفة (base16/reverse/base64/zlib/marshal). التوقف.")
            break

        # الخاتمة للتقرير
        report_lines.append("\n=== الخلاصة ===")
        report_lines.append(f"مجموع الطبقات المحاولة: {layer}")
        if saved_entries:
            report_lines.append("المدخلات المخزنة داخل الأرشيف:")
            for s in saved_entries:
                report_lines.append("  - " + s)
        else:
            report_lines.append("لم يُنتج أي مدخل مفكوك داخل الأرشيف.")

        # احفظ التقرير داخل الأرشيف
        report_text = "\n".join(report_lines)
        report_entry = f"{rel}/report.txt"
        ziph.writestr(report_entry, report_text.encode("utf-8", errors="ignore"))
        print(f"[إنهاء] عالجت {input_path} -> التقرير داخل: {report_entry}")


    def walk_and_process_into_zip(path: str, ziph: zipfile.ZipFile, root_base: str = ""):
        if os.path.isfile(path):
            if path.lower().endswith(".py"):
                print(f"[بدء] معالجة الملف: {path}")
                process_single_file_into_zip(path, ziph, root_base)
            else:
                print(f"[تخطي] ليس ملف Python: {path}")
            return

        for root, dirs, files in os.walk(path):
            for fn in files:
                if fn.lower().endswith(".py"):
                    full = os.path.join(root, fn)
                    print(f"[بدء] معالجة الملف: {full}")
                    try:
                        process_single_file_into_zip(full, ziph, root)
                    except Exception as e:
                        print(f"[خطأ] أثناء معالجة {full}: {e}")


    def interactive_loop(default_out_zip: Optional[str] = None):
        print("أدخل مسار ملف أو مجلد لتجربة فك التشفير (أدخل 'exit' أو اضغط Enter فارغ للخروج).")
        print("يمكنك أيضاً تمرير اسم أرشيف مخرجات افتراضي عبر الوسيط الثاني عند التشغيل.")
        while True:
            try:
                inp = input("مسار > ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nخروج.")
                break
            if not inp or inp.lower() == "exit":
                print("خروج.")
                break
            if not os.path.exists(inp):
                print(f"المسار غير موجود: {inp}")
                continue

            # اختر اسم الأرشيف (لكل إدخال سننشئ أرشيف منفصل لتفادي تداخل)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            if default_out_zip:
                out_zip = default_out_zip
            else:
                base_name = os.path.basename(os.path.abspath(inp)) or "results"
                out_zip = f"deobf_results_{base_name}_{timestamp}.zip"

            try:
                with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as ziph:
                    walk_and_process_into_zip(inp, ziph,
                                              os.path.dirname(os.path.abspath(inp)) if os.path.isdir(inp) else "")
                print(f"[نجاح] حُفظت النتائج في الأرشيف: {out_zip}\n")
            except Exception as e:
                print(f"[خطأ] تعذّر إنشاء الأرشيف {out_zip}: {e}")


    if __name__ == "__main__":
        # معالجة وسيطات سطر الأوامر
        if len(sys.argv) >= 2:
            target = sys.argv[1]
            if not os.path.exists(target):
                print(f"المسار غير موجود: {target}")
                sys.exit(1)
            # اسم الأرشيف إن أعطي (وسيط ثانٍ) أو افتراضي برمز زمني
            if len(sys.argv) >= 3:
                out_zip = sys.argv[2]
            else:
                ts = time.strftime("%Y%m%d_%H%M%S")
                base = os.path.basename(os.path.abspath(target)) or "results"
                out_zip = f"deobf_results_{base}_{ts}.zip"
            try:
                with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as ziph:
                    if os.path.isdir(target):
                        walk_and_process_into_zip(target, ziph, os.path.dirname(os.path.abspath(target)))
                    else:
                        walk_and_process_into_zip(target, ziph, "")
                print(f"\nتم حفظ الأرشيف: {out_zip}")
                sys.exit(0)
            except Exception as e:
                print(f"فشل إنشاء الأرشيف {out_zip}: {e}")
                sys.exit(1)
        else:
            interactive_loop()

if DECODE == "2":
    def deep_decrypt(path, max_layers=1000):
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
        current = text.encode("utf-8", errors="ignore")

        layers = 0
        for layer in range(1, max_layers + 1):
            try:
                # دور على base64
                m = re.search(rb'([A-Za-z0-9+/=\r\n]{100,})', current)
                if not m:
                    break

                b64_text = m.group(1).replace(b"\n", b"").replace(b"\r", b"")
                decoded = base64.b64decode(b64_text)
                decompressed = zlib.decompress(decoded)
                current = decompressed
                layers += 1
                print(f"✅ فكينا طبقة {layers}")
            except Exception as e:
                print(f"❌ توقف عند طبقة {layer}: {e}")
                break

        # حفظ الناتج النهائي فقط
        try:
            result = current.decode("utf-8")
        except:
            result = current.decode("latin-1", errors="replace")

        out_file = Path(path).with_suffix(".decoded.py")
        out_file.write_text(result, encoding="utf-8", errors="replace")
        print(f"\n📦 اكتمل الفك ({layers} طبقة) → الملف النهائي: {out_file}")
if DECODE == "3":
    def extract_bytes_from_ast(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=filepath)

        for node in ast.walk(tree):
            # نبحث عن marshal.loads(...) أو base64.b64decode(...)
            if isinstance(node, ast.Call):
                # الحالة المباشرة: marshal.loads(b'...')
                if isinstance(node.func, ast.Attribute) and node.func.attr == 'loads':
                    if node.args:
                        arg = node.args[0]
                        # مباشرة: b'...'
                        if isinstance(arg, ast.Constant) and isinstance(arg.value, bytes):
                            return arg.value
                        # مشفر base64: marshal.loads(base64.b64decode("..."))
                        elif isinstance(arg, ast.Call):
                            if isinstance(arg.func, ast.Attribute) and arg.func.attr == 'b64decode':
                                base64_arg = arg.args[0]
                                if isinstance(base64_arg, ast.Constant):
                                    base64_str = base64_arg.value
                                    try:
                                        return base64.b64decode(base64_str)
                                    except Exception as e:
                                        print(f"[!] فشل في فك base64: {e}")
        return None


    def decode_and_dis(code_bytes, output_path):
        try:
            code_obj = marshal.loads(code_bytes)
        except Exception as e:
            print(f"[!] خطأ في marshal.loads: {e}")
            return

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                for instr in dis.Bytecode(code_obj):
                    f.write(str(instr) + '\n')
            print(f"[+] تم حفظ التفكيك في: {output_path}")
        except Exception as e:
            print(f"[!] خطأ في dis: {e}")


    if __name__ == "__main__":
        print("📥 أدخل مسار ملف .py الذي يحتوي على الكائن المشفر:")
        src_file = input(">>> ").strip()

        if not os.path.exists(src_file):
            print(f"[!] الملف غير موجود: {src_file}")
            exit(1)

        print("💾 أدخل اسم الملف الذي سيتم حفظ النتيجة فيه (مثل output.txt):")
        out_file = input(">>> ").strip()

        code_bytes = extract_bytes_from_ast(src_file)
        if not code_bytes:
            print("[!] لم يتم العثور على كائن مشفر داخل الكود.")
            exit(1)

        decode_and_dis(code_bytes, out_file)
if DECODE == "4":
    def decrypt(encoded_data, key):
        decoded_bytes = base64.b64decode(encoded_data)
        decrypted = bytes([b ^ key for b in decoded_bytes])
        return decrypted.decode('utf-8', errors='ignore')


    def main():
        path = input("ادخل مسار الملف المشفر: ").strip()

        if not os.path.isfile(path):
            print("[!] الملف غير موجود في المسار المحدد.")
            return

        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()

            # استخراج المفتاح
            start_key = content.find("_loader_key_stub")
            if start_key == -1:
                raise Exception("لم يتم العثور على المفتاح.")

            key_line = content[start_key:].splitlines()[0]
            key = int(key_line.split("=")[-1].strip())

            # استخراج النص المشفر
            start_enc = content.find('"""')
            end_enc = content.find('"""', start_enc + 3)
            if start_enc == -1 or end_enc == -1:
                raise Exception("لم يتم العثور على النص المشفر.")

            encoded_data = content[start_enc + 3:end_enc].strip()

            # فك التشفير
            decoded = decrypt(encoded_data, key)

            print("\n[✓] تم فك التشفير بنجاح:\n")
            print(decoded)

            with open("decrypted_output.py", "w", encoding="utf-8") as out:
                out.write(decoded)

            print("\n[✓] تم حفظ الناتج في: decrypted_output.py")

        except Exception as e:
            print(f"[!] حدث خطأ أثناء فك التشفير: {e}")


    if __name__ == "__main__":
        main()
if DECODE == "5":
    def brute_decode_exec_base64(path):
        with open(path, 'r', encoding='utf-8') as f:
            code = f.read()

        # البحث يدويًا عن أول b64 مشفّر داخل exec
        start = code.find("exec(base64.b64decode(b'")
        if start == -1:
            print("❌ لم يتم العثور على exec(base64.b64decode(b'...'))")
            return

        # تحديد بداية ونهاية سلسلة base64
        start_b64 = code.find("b'", start) + 2
        end_b64 = code.find("')", start_b64)
        if start_b64 == -1 or end_b64 == -1:
            print("❌ لم يتم تحديد سلسلة base64 بشكل صحيح.")
            return

        b64_string = code[start_b64:end_b64]

        try:
            decoded_code = base64.b64decode(b64_string).decode('utf-8', errors='replace')
        except Exception as e:
            print("❌ فشل في فك التشفير:", e)
            return

        output_path = path.replace(".py", "_decoded.py")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(decoded_code)

        print(f"✅ تم فك التشفير بنجاح.\n📄 الملف الناتج: {output_path}")


    # مثال التشغيل:
    brute_decode_exec_base64 = input("حط مسار : ")
if DECODE == "6":
    def try_decode_layer(data):
        try:
            return zlib.decompress(base64.b64decode(data)).decode(errors='ignore')
        except Exception:
            return None


    def extract_encoded_from_exec(content):
        try:
            # نعزل الجزء داخل exec(...)
            start = content.find("b64decode(")
            if start == -1:
                return None
            start_quote = content.find("'", start)
            end_quote = content.find("'", start_quote + 1)
            return content[start_quote + 1:end_quote]
        except:
            return None


    def full_decode(path):
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            layer = 0
            while True:
                encoded = extract_encoded_from_exec(content)
                if not encoded:
                    break

                decoded = try_decode_layer(encoded)
                if not decoded:
                    break

                content = decoded
                layer += 1
                print(f"✅ تم فك الطبقة {layer}")

            if layer == 0:
                print("❌ لم يتم العثور على أي طبقة مشفّرة.")
                return

            output_name = "decode_" + os.path.basename(path)
            output_path = os.path.join(os.path.dirname(path), output_name)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)

            print(f"\n📁 الملف النهائي المفكوك: {output_path}")

        except Exception as e:
            print("❌ خطأ:", str(e))


    # 📂 تشغيل الأداة
    path = input("📂 eeأدخل مسار الملف المشفر: ").strip()
    full_decode(path)
if DECODE == "7":
    def extract_and_decode(filepath, decode_loops=50):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
        except Exception as e:
            print(f"❌ خطأ في فتح الملف: {e}")
            return

        # استخراج السلسلة من المتغير C
        match = re.search(r'C\s*=\s*["\'](.+?)["\']', content, re.DOTALL)
        if not match:
            print("❌ لم يتم العثور على المتغير C في الملف.")
            return

        encoded = match.group(1)

        try:
            for _ in range(decode_loops):
                encoded = zlib.decompress(base64.b64decode(encoded))
        except Exception as e:
            print(f"❌ خطأ أثناء فك التشفير: {e}")
            return

        # حفظ النتيجة في ملف جديد
        output_path = "decoded_output.py"
        try:
            with open(output_path, 'wb') as out_file:
                out_file.write(encoded)
            print(f"✅ تم حفظ الكود المفكوك في: {output_path}")
        except Exception as e:
            print(f"❌ تعذر حفظ الملف: {e}")


    # ========== التشغيل ==========
    if __name__ == "__main__":
        path = input("📂 fgأدخل مسار الملف المشفر: ").strip()
        if not os.path.isfile(path):
            print("❌ الملف غير موجود. تحقق من المسار.")
        else:
            extract_and_decode(path)
if DECODE == "8":
    def فك_تشفير(المسار):
        try:
            # قراءة محتوى الملف
            محتوى = Path(المسار).read_text(encoding="utf-8")

            # نمط محدد بناءً على طريقة التشفير المستخدمة في الملف
            نمط = re.search(r"\(b'(.*?)'\s*,compile\)", محتوى, re.DOTALL)
            if not نمط:
                print("❌ لم يتم العثور على بيانات مشفرة.")
                return

            # تحويل النص المشفر إلى بايتات
            بيانات = نمط.group(1).encode('utf-8').decode('unicode_escape').encode('latin1')

            # فك الضغط
            كود = zlib.decompress(بيانات).decode('utf-8')

            # حفظ الناتج
            اسم_الملف = "مفكوك_" + Path(المسار).stem + ".py"
            Path(اسم_الملف).write_text(كود, encoding="utf-8")
            print(f"✅ تم فك التشفير وحفظه في: {اسم_الملف}")

        except Exception as e:
            print(f"❌ خطأ أثناء فك التشفير: {e}")


    # تشغيل مباشر
    if __name__ == "__main__":
        مسار = input("📂 yueأدخل مسار الملف المشفر: ").strip()
        فك_تشفير(مسار)
if DECODE == "9":
    def decompress_bz2_file(input_path, output_path=None):
        if not os.path.exists(input_path):
            print(f"[!] الملف غير موجود: {input_path}")
            return

        try:
            # قراءة الملف المضغوط
            with open(input_path, "rb") as f:
                compressed_data = f.read()

            # فك الضغط
            decompressed_data = bz2.decompress(compressed_data)

            # تحديد المسار للملف الناتج
            if not output_path:
                output_path = input_path.replace(".bz2", "")

            # كتابة البيانات المفكوكة
            with open(output_path, "wb") as f:
                f.write(decompressed_data)

            print(f"[+] تم فك الضغط بنجاح: {output_path}")

        except Exception as e:
            print(f"[!] حدث خطأ أثناء فك الضغط: {e}")


    if __name__ == "__main__":
        input_file = input("ادخل مسار ملف BZ2: ").strip()
        decompress_bz2_file(input_file)

if DECODE == "10":
    # ----- إعداد اللوج (سيُعاد تهيئته عند التشغيل التلقائي لكتابة لملف) -----
    logger = logging.getLogger("unpack_obf")
    logger.setLevel(logging.INFO)
    _console_handler = logging.StreamHandler()
    _console_handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(_console_handler)

    # ----- تعابير منتظمة للبحث عن blobs -----
    BASE64_RE = re.compile(
        r"""(?P<quote>['"]{1,3})                # opening quote (1..3)
        (?P<data>(?:[A-Za-z0-9+/=\s\r\n]{200,})) # big base64-like blob (>=200 chars)
        (?P=quote)""",
        re.VERBOSE,
    )

    VAR_ASSIGN_RE = re.compile(
        r"""(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<quote>['"]{1,3})(?P<data>[A-Za-z0-9+/=\s\r\n]{200,})(?P=quote)""",
        re.VERBOSE,
    )


    def find_blobs(text: str) -> List[Tuple[str, Optional[str], str]]:
        """جمع كل الـ blobs المحتملة (نوع, var, data)"""
        results = []
        for m in VAR_ASSIGN_RE.finditer(text):
            results.append(("var", m.group("var"), m.group("data")))
        for m in BASE64_RE.finditer(text):
            results.append(("blob", None, m.group("data")))
        seen = set()
        out = []
        for t, v, b in results:
            key = (v, b[:80])
            if key in seen:
                continue
            seen.add(key)
            out.append((t, v, b))
        return out


    def try_decode(b64text: str) -> Optional[bytes]:
        b = "".join(b64text.split())
        try:
            return base64.b64decode(b, validate=True)
        except Exception:
            try:
                return base64.b64decode(b)
            except Exception:
                return None


    def is_zip(byts: bytes) -> bool:
        return byts.startswith(b"PK\x03\x04") or byts.startswith(b"PK\x05\x06") or byts.startswith(b"PK\x07\x08")


    def write_file(path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)


    def extract_zip(byts: bytes, outdir: str) -> Tuple[bool, Optional[str]]:
        td = tempfile.mkdtemp(prefix="unpack_obf_")
        p = os.path.join(td, "payload.zip")
        write_file(p, byts)
        try:
            with zipfile.ZipFile(p, "r") as z:
                z.extractall(outdir)
            shutil.rmtree(td, ignore_errors=True)
            return True, None
        except Exception as e:
            shutil.rmtree(td, ignore_errors=True)
            return False, str(e)


    # ----- واجهات أداة المساعدة -----
    def prompt_for_path() -> Optional[str]:
        while True:
            user_in = input("ادخل مسار ملف بايثون (أو اكتب q للخروج): ").strip()
            if user_in.lower() == "q":
                return None
            user_path = os.path.abspath(os.path.expanduser(user_in))
            if os.path.isfile(user_path):
                return user_path
            print(f"الملف '{user_path}' غير موجود. جرّب مسار صحيح أو اكتب q للخروج.\n")


    def process_file(fp: str, out_base: Optional[str] = None, keep_raw: bool = False, do_run: bool = False) -> None:
        logger.info(f"فتح الملف: {fp}")
        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

        blobs = find_blobs(text)
        if not blobs:
            logger.info("ما لَقيت أيّ blob شبيهة بـ base64 داخل الملف.")
            return

        logger.info(f"وجدت {len(blobs)} محتمل(ة). سأجرب فك كل واحدة بالترتيب.")
        base_out = out_base or os.path.join(os.getcwd(), f"unpacked_{os.path.splitext(os.path.basename(fp))[0]}")
        for idx, (typ, var, blob) in enumerate(blobs, 1):
            logger.info("-" * 60)
            logger.info(f"[{idx}] type={typ} var={var or '-'} size_text={len(blob)}")
            decoded = try_decode(blob)
            if decoded is None:
                logger.info("  -> فشل فك base64 لهذه القطعة.")
                continue
            logger.info(f"  -> تم فك base64 → {len(decoded)} بايت.")
            candidate_dir = os.path.join(base_out, f"blob_{idx}")
            os.makedirs(candidate_dir, exist_ok=True)

            if is_zip(decoded):
                logger.info("  -> باين إنه ZIP. بجرب استخرجه إلى: %s", candidate_dir)
                ok, err = extract_zip(decoded, candidate_dir)
                if ok:
                    logger.info("  -> تم الاستخراج. الملفات في: %s", candidate_dir)
                else:
                    logger.info("  -> محاولة الاستخراج فشلت: %s", err)
                    zippath = os.path.join(candidate_dir, "payload.zip")
                    write_file(zippath, decoded)
                    logger.info("  -> حفظت payload.zip في: %s", zippath)
            else:
                rawpath = os.path.join(candidate_dir, "payload.bin")
                write_file(rawpath, decoded)
                logger.info("  -> الملف المفكوك ليس ZIP. حفظت كـ: %s", rawpath)
                try:
                    txt = decoded.decode("utf-8")
                    snippet = "\n".join(txt.splitlines()[:30])
                    logger.info("  -> مقتطف أولي من المحتوى المفكوك (أول 30 سطر):\n%s", snippet)
                except Exception:
                    pass

            # خيار تشغيل — خطر!
            if do_run:
                main_py = os.path.join(candidate_dir, "main.py")
                if os.path.exists(main_py):
                    logger.warning(
                        "\n*** تحذير: أنت طلبت --run. تشغيل main.py قد يكون خطير. استمر على مسؤوليتك الخاصة. ***")
                    try:
                        subprocess.run([sys.executable, main_py], cwd=candidate_dir, check=False)
                    except Exception as e:
                        logger.error("خطأ عند محاولة التشغيل: %s", e)
                else:
                    logger.info("لم أجد main.py في المجلد لاشغاله.")
        logger.info("انتهى الفحص.")


    def main(argv: Optional[List[str]] = None) -> None:
        parser = argparse.ArgumentParser(description="Unpack obfuscated base64->zip embedded in Python file")
        parser.add_argument("--path", "-p", required=False,
                            help="مسار ملف بايثون الذي يحتوي الـ blob (إذا لم يُعطَ ستُطالَب تفاعليًا)")
        parser.add_argument("--out", "-o", default=None, help="مجلد استخراج (افتراضي: ./unpacked_<filename>)")
        parser.add_argument("--run", action="store_true",
                            help="تشغيل main.py داخل المجلد المستخرج بعد الاستخراج (خطر!)")
        parser.add_argument("--keep-raw", action="store_true", help="حفظ البايتات المفكوكة كملف raw إذا لم تكن zip")
        args = parser.parse_args(argv)

        if args.path:
            fp = os.path.abspath(args.path)
            if not os.path.isfile(fp):
                logger.error("ملف غير موجود: %s", fp)
                sys.exit(2)
        else:
            chosen = prompt_for_path()
            if chosen is None:
                logger.info("تم الإلغاء.")
                sys.exit(0)
            fp = chosen

        process_file(fp, out_base=args.out, keep_raw=args.keep_raw, do_run=args.run)


    # ----- تشغيل تلقائي غير تفاعلي عند الاستيراد إذا DECODE == "10" -----
    def _auto_run_if_requested_noninteractive():
        """
        السلوك:
          - يتحقق من globals().get("DECODE") أو os.environ["DECODE"] == "10"
          - يقرأ مسار الملف من (بترتيب الأولوية):
                1) globals().get("DECODE_PATH")
                2) os.environ.get("DECODE_PATH")
                3) './a.py' (افتراضي)
          - إذا الملف غير موجود: يطبع لوج ويرجع (لا يدخل وضع تفاعلي)
          - يهيئ لوج لكتابة ملف unpack_obf.log ثم يستدعي main مع --path <chosen_path>
        """
        module_decode = globals().get("DECODE", None)
        env_decode = os.environ.get("DECODE", None)
        if not (module_decode == "10" or env_decode == "10"):
            return

        # اختر المسار
        module_path = globals().get("DECODE_PATH", None)
        env_path = os.environ.get("DECODE_PATH", None)
        chosen_path = module_path or env_path or os.path.abspath("./a.py")

        # إعداد لوج ملف (نكتب كل شيء في unpack_obf.log)
        try:
            fh = logging.FileHandler("unpack_obf.log", encoding="utf-8")
            fh.setLevel(logging.INFO)
            fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
            # أضف إلى logger (لا تكرر إذا مضاف سابقًا)
            if not any(
                    isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None).endswith("unpack_obf.log")
                    for h in logger.handlers):
                logger.addHandler(fh)
        except Exception:
            # لو فشل إنشاء ملف لوج — استمر باللوج للكونسول
            pass

        if not os.path.isfile(chosen_path):
            logger.error("unpack_obf: التشغيل التلقائي مفعل (DECODE==10) لكن الملف غير موجود: %s", chosen_path)
            return

        # استدعي main بطريقة غير تفاعلية
        logger.info("unpack_obf: التشغيل التلقائي مفعل — سنفك الملف: %s", chosen_path)
        saved_argv = sys.argv[:]
        try:
            sys.argv = [saved_argv[0], "--path", chosen_path]
            main()
        except SystemExit:
            # main قد يستدعي sys.exit — تجاهل ذلك كي لا ينهار المضيف
            pass
        except Exception as e:
            logger.exception("unpack_obf: خطأ أثناء التشغيل التلقائي: %s", e)
        finally:
            sys.argv = saved_argv


    # ----- نقطة الدخول -----
    if __name__ == "__main__":
        main()
    else:
        # يُستدعى عند الاستيراد
        _auto_run_if_requested_noninteractive()

if DECODE == "11":
    # !/usr/bin/env python3
    """
    interactive_deobfuscate.py
    نسخة تفاعلية: تطلب المسار من المستخدم عند التشغيل وتنتج disassembly + .pyc

    شغّل:
        python interactive_deobfuscate.py
    وسيطلب المسار والإسم المبدئي للمخرجات.
    """

    import re
    import base64
    import zlib
    import marshal
    import dis
    import sys
    import importlib.util
    import time
    from pathlib import Path

    B64_PATTERN = re.compile(
        r"base64\.b64decode\(\s*(?:b'([^']+)'|b\"([^\"]+)\")\s*\)", re.DOTALL
    )


    def find_b64_strings(text):
        candidates = []
        for m in B64_PATTERN.finditer(text):
            s = m.group(1) or m.group(2)
            if s:
                s_clean = "".join(s.split())
                candidates.append(s_clean)
        return candidates


    def try_decode(b64_text):
        try:
            decoded = base64.b64decode(b64_text)
        except Exception as e:
            raise RuntimeError(f"base64 decode failed: {e}")
        try:
            decompressed = zlib.decompress(decoded)
        except Exception as e:
            raise RuntimeError(f"zlib decompress failed: {e}")
        try:
            code_obj = marshal.loads(decompressed)
        except Exception as e:
            raise RuntimeError(f"marshal.loads failed: {e}")
        return code_obj


    def write_disassembly(code_obj, out_path):
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("# Disassembly output (do NOT execute blindly)\n\n")
            if isinstance(code_obj, type((lambda: 0).__code__)):
                dis_out = dis.Bytecode(code_obj)
                for instr in dis_out:
                    f.write(str(instr) + "\n")
            else:
                f.write("# Returned object is not a code object. repr:\n")
                f.write(repr(code_obj))


    def write_pyc(code_obj, pyc_path):
        magic = importlib.util.MAGIC_NUMBER
        mtime = int(time.time())
        data = bytearray()
        data.extend(magic)
        data.extend(mtime.to_bytes(4, 'little'))
        data.extend((0).to_bytes(4, 'little'))
        data.extend(marshal.dumps(code_obj))
        with open(pyc_path, "wb") as f:
            f.write(data)


    def interactive_prompt():
        try:
            src = input("ادخل مسار الملف المراد فكّه (مثال: ./obf.py): ").strip()
            if not src:
                print("لم تدخل مساراً. الخروج.")
                sys.exit(1)
            out_stem = input("ادخل اسم مبدئي للمخرجات (الافتراضي 'recovered'): ").strip() or "recovered"
            return src, out_stem
        except (KeyboardInterrupt, EOFError):
            print("\nتم الإلغاء.")
            sys.exit(1)


    def main():
        src_path_str, out_name = interactive_prompt()
        src_path = Path(src_path_str)
        if not src_path.exists():
            print("خطأ: المسار غير موجود:", src_path, file=sys.stderr)
            sys.exit(2)

        text = src_path.read_text(encoding="utf-8", errors="ignore")
        candidates = find_b64_strings(text)
        if not candidates:
            print("لم أجد نمط base64.b64decode(...) داخل الملف. تأكد أن الملف يحتوي على b'...'.", file=sys.stderr)
            sys.exit(3)

        last_err = None
        out_stem = Path(out_name)
        for i, c in enumerate(candidates, start=1):
            try:
                print(f"محاولة فك المرشح #{i} ...")
                code_obj = try_decode(c)
                dis_path = out_stem.with_suffix(".dis.txt")
                pyc_path = out_stem.with_suffix(".pyc")
                write_disassembly(code_obj, dis_path)
                write_pyc(code_obj, pyc_path)
                print("نجحت! الملفات التالية تم انتاجها:")
                print(" - disassembly:", dis_path.resolve())
                print(" - pyc file:", pyc_path.resolve())
                print("\nتحذير: لا تقم بتشغيل (exec) المحتوى المنتَج دون فحصه يدوياً.")
                return
            except Exception as e:
                last_err = e
                print(f"المرشح #{i} فشل: {e}")

        print("فشل فكّ جميع المرشحين. آخر خطأ:", last_err, file=sys.stderr)
        sys.exit(4)


    if __name__ == "__main__":
        main()
    else:

        _auto_run_if_requested_noninteractive()
if DECODE == "12":

    # Patterns for quoted strings (single/double/triple)
    QUOTED_RE = re.compile(r"('{3}.*?'{3}|\"{3}.*?\"{3}|'[^']*'|\"[^\"]*\")", re.DOTALL)
    BASE64_CHARS = re.compile(r"[A-Za-z0-9+/=]+")


    def prompt_input_path():
        while True:
            p = input("ادخل مسار ملف البايثون المشفّر (او اكتب 'exit'): ").strip()
            if not p:
                print("رجاءً اكتب مسار.")
                continue
            if p.lower() in ('exit', 'quit'):
                sys.exit(0)
            path = Path(p).expanduser()
            if path.exists() and path.is_file():
                return path
            print("الملف غير موجود. حاول مرّة ثانية.")


    def prompt_max_layers(default=20):
        s = input(f"أدخل أقصى عدد طبقات للفك (default {default}): ").strip()
        if not s:
            return default
        try:
            v = int(s)
            return max(1, v)
        except:
            return default


    def gather_string_literals(text):
        # returns list of (start, end, inner_content)
        items = []
        for m in QUOTED_RE.finditer(text):
            token = m.group(0)
            if token.startswith(("'''", "\"\"\"")):
                inner = token[3:-3]
            else:
                inner = token[1:-1]
            items.append((m.start(), m.end(), inner))
        return items


    def is_b64_like(s, min_len=200):
        # consider it candidate if it has many base64 chars
        only = "".join(BASE64_CHARS.findall(s))
        return len(only) >= min_len, only


    def try_decode_reversed(b64_like_bytes):
        try:
            # input is str of base64 chars -> encode then reverse
            rev = b64_like_bytes[::-1].encode('latin1', errors='surrogatepass')
            return base64.b64decode(rev)
        except Exception:
            return None


    def decode_candidates(text, max_layers=20):
        literals = gather_string_literals(text)
        candidates = []
        # check each literal if it looks like base64 (long)
        for i, (st, ed, inner) in enumerate(literals):
            ok, only = is_b64_like(inner, min_len=200)
            if not ok:
                continue
            # try iterative decoding: reverse -> b64decode -> if result contains another literal, continue
            current = only  # only base64-like chars
            layers = 0
            last = None
            while layers < max_layers:
                dec = try_decode_reversed(current)
                if dec is None:
                    break
                layers += 1
                last = dec
                # try find quoted literal inside decoded text to continue
                try:
                    decoded_text = dec.decode('utf-8', errors='replace')
                except:
                    decoded_text = None
                if decoded_text:
                    inner_matches = QUOTED_RE.search(decoded_text)
                    if inner_matches:
                        # take inner content of first quoted match and extract only base64-like chars
                        token = inner_matches.group(0)
                        if token.startswith(("'''", "\"\"\"")):
                            inner2 = token[3:-3]
                        else:
                            inner2 = token[1:-1]
                        ok2, only2 = is_b64_like(inner2, min_len=40)  # smaller threshold now
                        if ok2:
                            current = only2
                            continue
                break
            if last is not None:
                candidates.append({'index': i, 'start': st, 'end': ed, 'layers': layers, 'bytes': last})
        # sort by layers desc then length
        candidates.sort(key=lambda x: (x['layers'], len(x['bytes'] or b"")), reverse=True)
        return candidates


    def main():
        print("=== اداة فك reversed-base64 (نسخة محسّنة) ===")
        infile = prompt_input_path()
        max_layers = prompt_max_layers(20)
        try:
            text = infile.read_text(errors='surrogatepass')
        except Exception as e:
            print("خطأ بقراءة الملف:", e)
            sys.exit(2)
        candidates = decode_candidates(text, max_layers=max_layers)
        if not candidates:
            print("ما لقيت سلاسل base64 مناسبة للفك.")
            sys.exit(1)
        best = candidates[0]
        default_out = infile.with_suffix(infile.suffix + ".decoded.py")
        out = input(f"ادخل مسار الحفظ (اضغط Enter للحفظ كـ {default_out}): ").strip()
        out_path = Path(out).expanduser() if out else default_out
        try:
            out_path.write_bytes(best['bytes'])
            print(f"كتبت أفضل نتيجة (layers={best['layers']}) إلى: {out_path}")
            try:
                sample = best['bytes'].decode('utf-8', errors='replace')
                print("\n--- معاينة أوّل 1000 حرف ---\n")
                print(sample[:1000])
            except:
                print("\nالمحتوى ثنائي، لم أتمكن من عرضه كنص.")
        except Exception as e:
            print("خطأ بكتابة الملف:", e)
            sys.exit(3)
        print("\nملاحظة أمان: لا تشغّل الملف المفكوك قبل مراجعته يدوياً.")


    if __name__ == '__main__':
        main()
    else:
        _auto_run_if_requested_noninteractive()