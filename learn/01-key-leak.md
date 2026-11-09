# ข้อ 1: key หลุด

**ภาษาไทย** | [English](01-key-leak.en.md)

[กลับไปหน้าลำดับการตรวจ](README.md)

## คำศัพท์

- **key หรือ secret**: รหัสที่แอปใช้ยืนยันตัวกับบริการอื่น เช่น รหัสเรียกระบบรับเงิน รหัสฐานข้อมูล หรือ token ของ AI ใครได้ไปก็ใช้บริการนั้นในนามคุณได้
- **ผู้ให้บริการ**: เจ้าของบริการที่ออก key ให้คุณ เช่น Stripe, Supabase, OpenAI
- **หมุน key (rotate)**: ยกเลิก key เดิมที่หน้าเว็บของผู้ให้บริการ แล้วออก key ใหม่ key เดิมจะใช้ไม่ได้อีก
- **git**: ระบบเก็บประวัติการแก้โค้ดทุกครั้ง
- **commit**: การบันทึกโค้ดหนึ่งครั้งลง git
- **push**: การส่ง commit จากเครื่องขึ้นไปเก็บบน GitHub
- **pre-commit hook**: คำสั่งที่ git รันเองก่อน commit ทุกครั้ง ถ้าคำสั่งนั้นไม่ผ่าน จะ commit ไม่ได้
- **git history**: commit ทั้งหมดที่ผ่านมา ของที่ลบจากไฟล์ล่าสุดแล้วยังดูย้อนหลังได้จากตรงนี้
- **`.gitignore`**: ไฟล์รายชื่อของที่ไม่ให้ git เก็บ
- **`.env`**: ไฟล์เก็บค่าตั้งของแอปบนเครื่อง มักใช้เก็บ key และไม่ควรเข้า git
- **environment variable**: ค่าที่แอปอ่านจากเครื่องที่รันอยู่ ทำให้ไม่ต้องเขียน key ลงในโค้ด
- **frontend**: โค้ดที่รันในเบราว์เซอร์ของคนใช้ ทุกคนเปิดอ่านได้
- **backend หรือ server**: โค้ดที่รันบนเครื่องของคุณ คนใช้มองไม่เห็น
- **build**: ขั้นตอนแปลงโค้ดเป็นไฟล์ที่เอาขึ้นเว็บจริง ผลมักอยู่ในโฟลเดอร์ `dist/`, `build/` หรือ `.next/static/`
- **deploy**: การเอาแอปขึ้นเซิร์ฟเวอร์ให้คนอื่นใช้
- **finding**: ปัญหาหนึ่งรายการที่เครื่องมือรายงาน

## ทำไมต้องเริ่มข้อนี้

key ไม่ต้องเจาะระบบ ใครเจอก็ใช้ได้เลย มาตรฐาน [CWE-798][cwe] เรียกปัญหานี้ว่าการฝังรหัสไว้ในตัวโปรแกรม ข้อนี้ตรวจด้วยเครื่องมือได้และใช้เวลาไม่กี่นาที จึงเหมาะเป็นเรื่องแรก

## key หลุดได้ทางไหนบ้าง

1. **เขียนลงในโค้ดตรง ๆ** AI มักทำแบบนี้เมื่อเราส่ง key ให้แล้วบอกว่า "ทำให้ใช้ได้"
2. **commit แล้วค่อยลบ** ไฟล์ล่าสุดไม่มี key แล้ว แต่ git history ยังเก็บไว้ คนที่มีสำเนา repo ยังเปิดดูได้
3. **ลืมใส่ `.env` ใน `.gitignore`** พอ commit ไฟล์นี้จะเข้า git ไปทั้งไฟล์
4. **ใส่ key ในตัวแปรที่ถูกส่งไป frontend** [เอกสารของ Vite][vite] ระบุว่าตัวแปรที่ขึ้นต้น `VITE_` จะอยู่ในโค้ดฝั่งเบราว์เซอร์หลัง build และไม่ควรเก็บ key ส่วน [เอกสารของ Next.js][next] ระบุว่าตัวแปร `NEXT_PUBLIC_` ถูกฝังลงไฟล์ที่ส่งให้เบราว์เซอร์ตอน build ไฟล์ต้นฉบับอาจดูสะอาด แต่ key ไปโผล่ในไฟล์ build

## ลองกับแอปตัวอย่างก่อน

ต้องมี Node.js และ git คำสั่งนี้สร้างแอปปลอมที่มี key ปลอมซึ่งสุ่มตอนรัน ไม่ต้องกลัวว่าจะกระทบอะไร ถ้าใช้ Windows ให้เปลี่ยน `/tmp/demo-app` เป็นโฟลเดอร์ว่างที่ไหนก็ได้

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
node ai-secure-audit/examples/vulnerable-app/setup.mjs /tmp/demo-app
node ai-secure-audit/bin/ai-secure-audit.js /tmp/demo-app
```

ควรเห็นบรรทัดนี้

```text
0 critical · 2 high · 0 medium · 0 low
```

เปิด `/tmp/demo-app/.audit/out/report.md` จะเห็นปัญหาสองข้อ ข้อแรกคือ key ที่อยู่ในโค้ด `src/web/config.js` ข้อสองคือ `.env` ที่มีป้าย `(git history only)` แปลว่าลบไฟล์ไปแล้ว แต่ key ยังอยู่ในประวัติ

## ตรวจโปรเจกต์ของตัวเอง

เปิด terminal ในโฟลเดอร์โปรเจกต์แล้วรัน

```bash
npx ai-secure-audit
```

หรือบอก AI ที่ใช้อยู่ว่า

> รัน `npx ai-secure-audit` ในโปรเจกต์นี้ อธิบายผลให้คนที่ไม่รู้เรื่อง security เข้าใจ แล้วช่วยแก้ทีละข้อโดยเริ่มจากข้อที่ร้ายแรงที่สุด ห้ามเพิ่มหรือลบ finding เอง

เครื่องมือรันบนเครื่องของคุณและไม่ส่งโค้ดออกไป แต่ถ้าให้ AI อ่านผล ข้อมูลที่ AI อ่านจะถูกส่งไปหาผู้ให้บริการ AI นั้น ผลอยู่ที่ `.audit/out/report.md` และโฟลเดอร์นี้ไม่เข้า git

## อ่านผลยังไง

| ที่เห็นในรายงาน | ความหมาย | ต้องหมุน key ไหม |
|---|---|---|
| `(not committed yet)` | อยู่ในไฟล์ แต่ยังไม่เข้า git | ถ้ายังไม่เคยส่งให้ใครหรือวางที่ไหน ย้ายออกจากโค้ดก็พอ |
| ไม่มีป้าย มีเลข commit | อยู่ในไฟล์และอยู่ใน git แล้ว | ต้องหมุน |
| `(git history only)` | ลบจากไฟล์แล้ว แต่ยังอยู่ในประวัติ | ต้องหมุน |
| `(build output)` | อยู่ในไฟล์ที่เอาขึ้นเว็บ | ถ้าเคย deploy แล้ว ต้องหมุน |

ถ้าเป็น `(build output)` ระดับ medium รายงานจะบอกว่าอาจเตือนผิด เพราะโค้ดที่ถูกย่อบางส่วนหน้าตาคล้าย key ให้ดูค่าจริงก่อนตัดสิน

## แก้ตามลำดับนี้

1. **หมุน key ก่อน** ที่หน้าเว็บของผู้ให้บริการ [คู่มือของ GitHub][github] บอกว่าขั้นแรกต้องยกเลิกหรือหมุน key และเตือนว่าการลบประวัติอย่างเดียวไม่พอ เพราะ commit เก่าอาจยังอยู่ในสำเนาของคนอื่น
2. **เอา key ออกจากโค้ด** แล้วให้ backend อ่านจาก environment variable แทน
3. **ถ้าเป็น key ที่อยู่ใน frontend ให้ย้ายงานนั้นไป backend** หน้าเว็บเรียก backend ของคุณ แล้ว backend ค่อยเรียกผู้ให้บริการ เปลี่ยนชื่อตัวแปรอย่างเดียวไม่ได้แก้ปัญหา ถ้าโค้ด frontend ยังใช้ key นั้นอยู่
4. **ใส่ `.env` ใน `.gitignore`** ถ้าเคย commit ไปแล้ว ต้องสั่งเลิกติดตามด้วย เพราะ [เอกสารของ git][gitignore] ระบุว่า `.gitignore` ไม่มีผลกับไฟล์ที่ git เก็บอยู่แล้ว

   ```bash
   git rm --cached .env
   ```

5. **build ใหม่** ถ้าปัญหาอยู่ในไฟล์ build ไฟล์เก่าจะยังมี key จนกว่าจะ build ทับ
6. **ตรวจซ้ำ**

   ```bash
   npx ai-secure-audit retest
   ```

ถ้า key เคยเข้า git แล้ว `retest` จะยังขึ้น `still open` แม้หมุน key แล้ว เพราะ key เก่ายังอยู่ในประวัติ และเครื่องมือไม่มีทางรู้ว่ามันถูกยกเลิกแล้ว [คู่มือของ GitHub][github] บอกว่าการหมุน key อาจเพียงพอ และการเขียนประวัติใหม่อาจไม่คุ้ม ถ้าหมุนแล้วก็ถือว่าข้อนี้จบได้ ให้จดไว้เองว่าหมุนเมื่อไร

## ดักก่อน push

หัวข้อก่อนหน้าคือวิธีแก้หลัง key หลุด หัวข้อนี้คือวิธีกันไม่ให้หลุดอีก ตั้งไว้สองชั้น ชั้นแรกอยู่บนเครื่องของคุณ ชั้นที่สองอยู่บน GitHub

### ชั้นที่ 1: pre-commit hook บนเครื่อง

ให้ [gitleaks][gitleaks] ตรวจทุกครั้งก่อน commit ถ้าเจอ key จะ commit ไม่ได้ key จึงไม่เข้า git history ตั้งแต่แรก

1. ติดตั้ง [pre-commit][precommit] ครั้งเดียวต่อเครื่อง (ต้องมี Python) ถ้าใช้ Mac ที่มี Homebrew ใช้ `brew install pre-commit` แทนได้

   ```bash
   pipx install pre-commit
   ```

2. สร้างไฟล์ `.pre-commit-config.yaml` ที่โฟลเดอร์บนสุดของโปรเจกต์ (`v8.30.1` คือรุ่นเดียวกับที่ `npx ai-secure-audit` ใช้)

   ```yaml
   repos:
     - repo: https://github.com/gitleaks/gitleaks
       rev: v8.30.1
       hooks:
         - id: gitleaks
   ```

3. เปิดใช้ในโปรเจกต์

   ```bash
   pre-commit install
   ```

ข้อควรรู้

- hook ทำงานเฉพาะในเครื่องที่รัน `pre-commit install` แล้ว เพื่อนในทีมหรือเครื่องใหม่ต้องรันเองด้วย
- ข้าม hook ได้ด้วย `SKIP=gitleaks git commit ...` หรือ `git commit --no-verify` ถ้าให้ AI commit แทน ให้บอก AI ว่าห้ามข้าม hook
- hook ไม่ตรวจของที่ commit ไปก่อนติดตั้ง ของเก่าให้ตรวจด้วย `npx ai-secure-audit`

### ชั้นที่ 2: Push Protection บน GitHub

GitHub ตรวจตอนที่คุณ push ถ้าเจอ key ที่รู้จักรูปแบบ จะไม่รับ push นั้น key จึงไม่ขึ้นไปอยู่บน GitHub ([เอกสารของ GitHub][pushabout])

- **ของบัญชีคุณ**: เปิดอยู่แล้วโดยค่าเริ่มต้น กันการ push key ขึ้น repo สาธารณะ เช็กได้ที่ รูปโปรไฟล์ → Settings → Code security → "Push protection for yourself" ([วิธีเช็ก][pushusers])
- **ของ repo**: ไปที่ repo → Settings → Advanced Security (หมวด Security and quality) → เปิด Secret Protection แล้วกด Enable ที่ Push protection ([วิธีเปิด][pushrepo]) แบบนี้กันได้ทุกคนที่ push เข้า repo นั้น ไม่ใช่แค่ตัวคุณ repo สาธารณะเปิดได้ฟรี ส่วน repo private ต้องซื้อ GitHub Secret Protection ([เอกสารของ GitHub][ghas])

ถ้าโดนบล็อก ให้เอา key ออกจาก commit นั้นก่อนแล้วค่อย push ใหม่ ([วิธีของ GitHub][pushcli]) ถ้าบอกให้ AI ทำ ให้บอกด้วยว่าห้ามกดข้าม

ข้อควรรู้

- จับได้เฉพาะ key ที่ GitHub รู้จักรูปแบบ ([รายชื่อ][patterns])
- คนที่มีสิทธิ์เขียน repo กดข้ามการบล็อกได้ โดยเลือกเหตุผล เช่น "It's used in tests"
- ไม่ช่วย repo ที่อยู่ที่อื่น เช่น GitLab และไม่ลบ key ที่เคยขึ้นไปแล้ว ของที่ขึ้นไปแล้วให้แก้ตามหัวข้อก่อนหน้า

สองชั้นนี้ช่วยกันคนละจุด hook จับก่อน key เข้า git history ส่วน Push Protection จับตอน push แม้ในเครื่องนั้นไม่ได้ติดตั้ง hook ไว้

## key บางตัวเปิดเผยได้ตามที่ผู้ให้บริการออกแบบ

ถ้าเครื่องมือหรือ AI เตือน key พวกนี้ ให้เช็กชนิดของ key ก่อน

| บริการ | ใส่ใน frontend ได้ | ห้ามใส่ใน frontend |
|---|---|---|
| [Stripe][stripe] | publishable key (`pk_...`) | secret key (`sk_...`) และ restricted key (`rk_...`) |
| [Supabase][supabase] | publishable key (`sb_publishable_...`) หรือ `anon` รุ่นเก่า | secret key (`sb_secret_...`) หรือ `service_role` รุ่นเก่า |
| [Firebase][firebase] | API key ของบริการ Firebase | Gemini Developer API key |

"ใส่ได้" ไม่ได้แปลว่าปลอดภัยโดยอัตโนมัติ [เอกสารของ Firebase][firebase] เตือนให้ตั้ง Security Rules เพื่อป้องกันข้อมูล เรื่องนี้คือข้อ 3 ใน[ลำดับการตรวจ](README.md)

## สิ่งที่การตรวจนี้มองไม่เห็น

- key ที่รูปแบบไม่ตรงกับกฎของ [gitleaks][gitleaks] เครื่องมือหาจากรูปแบบที่รู้จัก จึงพลาดได้
- key ที่เคยส่งในแชต วางในเอกสาร หรืออยู่บนเซิร์ฟเวอร์ที่ deploy ไปแล้ว
- ไฟล์ที่ใหญ่เกิน 20 MB
- โฟลเดอร์ `node_modules/`, `vendor/`, `coverage/`
- ไฟล์ที่ git ignore ซึ่งไม่ใช่ไฟล์ build เพราะถือว่าอยู่แค่บนเครื่องของคุณ

## แหล่งอ้างอิง

เข้าถึงเมื่อ 9 พฤศจิกายน 2569

- [CWE-798: Use of Hard-coded Credentials][cwe]
- [GitHub Docs: Removing sensitive data from a repository][github]
- [Git: gitignore][gitignore]
- [Vite: Env Variables and Modes][vite]
- [Next.js: How to use environment variables][next]
- [Stripe: API keys][stripe]
- [Supabase: API keys][supabase]
- [Firebase: Learn about using and managing API keys][firebase]
- [gitleaks][gitleaks]
- [pre-commit][precommit]
- [GitHub Docs: About push protection][pushabout]
- [GitHub Docs: Push protection for users][pushusers]
- [GitHub Docs: Enabling push protection for your repository][pushrepo]
- [GitHub Docs: Working with push protection from the command line][pushcli]
- [GitHub Docs: Supported secret scanning patterns][patterns]
- [GitHub Docs: About GitHub Advanced Security][ghas]

[cwe]: https://cwe.mitre.org/data/definitions/798.html
[github]: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository
[gitignore]: https://git-scm.com/docs/gitignore
[vite]: https://vite.dev/guide/env-and-mode
[next]: https://nextjs.org/docs/app/guides/environment-variables
[stripe]: https://docs.stripe.com/keys
[supabase]: https://supabase.com/docs/guides/api/api-keys
[firebase]: https://firebase.google.com/docs/projects/api-keys
[gitleaks]: https://github.com/gitleaks/gitleaks
[precommit]: https://pre-commit.com/
[pushabout]: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
[pushusers]: https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/push-protection-for-users
[pushrepo]: https://docs.github.com/en/code-security/secret-scanning/enabling-secret-scanning-features/enabling-push-protection-for-your-repository
[pushcli]: https://docs.github.com/en/code-security/secret-scanning/working-with-secret-scanning-and-push-protection/working-with-push-protection-from-the-command-line
[patterns]: https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns
[ghas]: https://docs.github.com/en/get-started/learning-about-github/about-github-advanced-security
