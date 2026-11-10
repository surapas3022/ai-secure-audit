# ข้อ 5: library มีช่องโหว่

**ภาษาไทย** | [English](05-vulnerable-libraries.en.md)

[กลับไปหน้าลำดับการตรวจ](README.md)

## คำศัพท์

- **library หรือ package**: โค้ดที่คนอื่นเขียนไว้แล้ว แอปของคุณดึงมาใช้ เช่น `express` ไว้ทำเว็บเซิร์ฟเวอร์ หรือ `lodash` ไว้จัดการข้อมูล
- **dependency**: library ที่แอปต้องใช้ ถ้าไม่มีแอปจะรันไม่ได้
- **dependency ของ dependency**: library ที่ library ของคุณดึงมาใช้ต่ออีกที คุณไม่ได้สั่งติดตั้งเอง แต่ก็อยู่ในแอปของคุณ สั่งติดตั้ง 3 ตัวอาจได้มาหลายสิบตัว
- **npm**: เครื่องมือติดตั้ง library ของ JavaScript และ Node.js
- **`package.json`**: ไฟล์รายชื่อ library ที่แอปต้องการ บอกเป็นช่วงเวอร์ชันได้ เช่น `^1.2.5`
- **`^` หน้าเลขเวอร์ชัน**: [เอกสารของ npm][npmjson] เรียกว่า "Compatible with version" เช่น `^1.0.4` ยอมรับรุ่นย่อยที่ใหม่กว่าในเลขหลักแรกเดียวกัน
- **lockfile**: ไฟล์ที่จดเวอร์ชันจริงของ library ทุกตัวที่ติดตั้งลงไป รวม dependency ของ dependency ด้วย ของ npm คือ `package-lock.json` ของ pnpm คือ `pnpm-lock.yaml` ของ yarn คือ `yarn.lock`
- **ช่องโหว่ที่ประกาศแล้ว (advisory)**: ประกาศว่า library ตัวไหน เวอร์ชันไหนมีจุดอ่อน แก้แล้วในเวอร์ชันไหน
- **CVE**: เลขประจำตัวของช่องโหว่หนึ่งตัวที่ใช้กันทั้งโลก เช่น `CVE-2021-44906` ทุกเว็บที่พูดถึงช่องโหว่ตัวนี้ใช้เลขเดียวกัน
- **GHSA**: เลขประจำตัวของประกาศในฐานข้อมูลของ GitHub เช่น `GHSA-xvch-5gv4-984h` ช่องโหว่ตัวเดียวกันมักมีทั้ง CVE และ GHSA
- **CVSS**: คะแนนความร้ายแรงของช่องโหว่ 0 ถึง 10 ยิ่งสูงยิ่งร้าย
- **OSV**: ฐานข้อมูลช่องโหว่ของ open source ที่รวมประกาศจากหลายแหล่งไว้ที่เดียว รวมถึงฐานข้อมูลของ GitHub
- **finding**: ปัญหาหนึ่งรายการที่เครื่องมือรายงาน

## ทำไมเรื่องนี้สำคัญ

ช่องโหว่ของ library ที่ประกาศแล้ว คนทั้งโลกรู้วิธีโจมตีพร้อมกัน คนโจมตีแค่หาแอปที่ยังใช้เวอร์ชันนั้นอยู่ [OWASP Top 10:2025][owasp] จัดหมวด "A03:2025 - Software Supply Chain Failures" ไว้เป็นอันดับ 3 ของความเสี่ยงเว็บแอป ซึ่งรวมปัญหาจาก library ที่แอปดึงมาใช้

ข่าวดีคือส่วนใหญ่แก้ได้ด้วยการอัปเดตเป็นเวอร์ชันที่แก้แล้ว ไม่ต้องแก้โค้ดของตัวเอง

## library เก่าเข้ามาในแอปได้ยังไง

1. **AI เขียนเลขเวอร์ชันจากความจำ** AI รู้จัก library จากข้อมูลที่เรียนมาตอนสร้าง ถ้ามันเขียน `package.json` เองโดยไม่ได้สั่ง `npm install` อาจได้เวอร์ชันเก่าที่มีช่องโหว่ประกาศไปแล้ว
2. **ใช้ template หรือโปรเจกต์เก่าเป็นจุดเริ่ม** lockfile ล็อกเวอร์ชันเดิมไว้ ติดตั้งกี่รอบก็ได้เวอร์ชันเดิม
3. **ไม่ได้ทำอะไรผิดเลย แค่เวลาผ่านไป** วันที่ติดตั้งยังไม่มีใครเจอช่องโหว่ เดือนหน้ามีคนเจอและประกาศ เวอร์ชันที่คุณใช้อยู่ก็กลายเป็นเวอร์ชันมีช่องโหว่ทันที แปลว่าต้องตรวจซ้ำเป็นระยะ ไม่ใช่ตรวจครั้งเดียวจบ
4. **มากับ dependency ของ dependency** คุณอัปเดต library ที่สั่งติดตั้งเองแล้ว แต่ตัวที่มันดึงมาใช้ต่ออาจยังเก่า

## ลองกับตัวอย่างก่อน

ต้องมี Node.js คำสั่งนี้สร้างโฟลเดอร์ทดลองที่ล็อก library สองตัวไว้ที่เวอร์ชันเก่า `--package-lock-only` คือเขียนแค่ lockfile ไม่ได้ติดตั้งโค้ดจริงลงเครื่อง และ `--ignore-scripts` คือไม่รันสคริปต์ของ library ไม่มีโค้ดเก่าตัวไหนได้ทำงาน

```bash
git clone https://github.com/surapas3022/ai-secure-audit.git
mkdir demo-libs && cd demo-libs
npm init -y
npm install minimist@1.2.5 lodash@4.17.20 --save-exact --package-lock-only --ignore-scripts
node ../ai-secure-audit/bin/ai-secure-audit.js .
```

ครั้งแรกจะช้าหน่อย เพราะต้องโหลดตัวเครื่องมือและฐานข้อมูลช่องโหว่ (ของ npm ราว 210 MB) วันที่ 10 พฤศจิกายน 2569 ได้บรรทัดนี้

```text
1 critical · 2 high · 2 medium · 0 low
```

ถ้าคุณได้มากกว่านี้ไม่ใช่เรื่องผิด แปลว่ามีคนเจอช่องโหว่เพิ่มในเวอร์ชันเก่าพวกนี้ ฐานข้อมูลโตขึ้นทุกวัน

เปิด `.audit/out/report.md` จะเห็นข้อแรกเป็น `minimist 1.2.5: Prototype Pollution in minimist` และวิธีแก้ `Upgrade minimist to 1.2.6 or later` ตรงกับ [ประกาศของ GitHub][ghminimist] ที่บอกว่าเวอร์ชันก่อน 1.2.6 มีช่องโหว่ และแก้แล้วใน 1.2.6

ลองแก้ดู

```bash
npm install minimist@latest lodash@latest --save-exact --package-lock-only --ignore-scripts
node ../ai-secure-audit/bin/ai-secure-audit.js retest
```

ควรได้ `0 critical · 0 high · 0 medium · 0 low`

## ตรวจโปรเจกต์ของตัวเอง

เปิด terminal ในโฟลเดอร์โปรเจกต์แล้วรัน

```bash
npx ai-secure-audit
```

หรือบอก AI ที่ใช้อยู่ว่า

> รัน `npx ai-secure-audit` ในโปรเจกต์นี้ อธิบายผลให้คนที่ไม่รู้เรื่อง security เข้าใจ แล้วช่วยแก้ทีละข้อโดยเริ่มจากข้อที่ร้ายแรงที่สุด ห้ามเพิ่มหรือลบ finding เอง

เครื่องมืออ่าน lockfile ทุกไฟล์ในโปรเจกต์ แล้วเทียบกับสำเนาของฐานข้อมูล OSV ที่โหลดมาไว้ในเครื่อง รายชื่อ library ของคุณไม่ถูกส่งออกไปไหน ต่างจาก `npm audit` ที่ [เอกสารของ npm][npmaudit] ระบุว่าส่งรายละเอียด dependency ของโปรเจกต์ไปที่ registry เพื่อขอรายงาน ทั้งสองแบบใช้ได้ แค่ควรรู้ว่าข้อมูลไปไหน

ต้องมี lockfile ถ้าโปรเจกต์มีแค่ `package.json` ให้รัน `npm install` ก่อน ไม่อย่างนั้นจะได้ 0 ข้อทั้งที่อาจมีปัญหา

## อ่านผลยังไง

แต่ละข้อบอก 4 อย่าง สามอย่างแรกอยู่ใน `report.md` เลขประกาศกับคะแนนอยู่ใน `.audit/out/findings.json`

| ส่วน | ตัวอย่าง | ความหมาย |
|---|---|---|
| ชื่อ | `lodash 4.17.20: Command Injection in lodash` | library ตัวไหน เวอร์ชันไหน ช่องโหว่แบบไหน |
| ที่อยู่ | `package-lock.json` | lockfile ไฟล์ไหน |
| วิธีแก้ | `Upgrade lodash to 4.17.21 or later` | เวอร์ชันที่แก้แล้ว |
| เลขประกาศ (`findings.json`) | `Advisories: CVE-2021-23337, GHSA-35jh-r3h4-6jhm` | เอาไปค้นอ่านรายละเอียดได้ เช่น [ประกาศของ GitHub][ghlodash] |

ระดับความร้ายแรงมาจากคะแนน CVSS ตาม [ตารางของ FIRST][cvss] ผู้ดูแลมาตรฐานนี้ คะแนนจริงอยู่ในช่อง `severity.tool` ของ `findings.json` เช่น `CVSS 7.2`

| คะแนน | ระดับในรายงาน |
|---|---|
| 9.0 – 10.0 | critical |
| 7.0 – 8.9 | high |
| 4.0 – 6.9 | medium |
| 0.1 – 3.9 | low |

ประกาศที่ไม่มีคะแนน รายงานจะใส่เป็น medium และ `severity.tool` เป็น `unrated`

ช่องโหว่ใน library ไม่ได้แปลว่าแอปโดนโจมตีได้เสมอ บางทีช่องโหว่อยู่ในฟังก์ชันที่แอปไม่ได้เรียกเลย แต่การดูว่าเรียกหรือไม่เรียกต้องอ่านโค้ดลึก การอัปเดตเร็วกว่าและชัวร์กว่า

## แก้ตามลำดับนี้

1. **อัปเดตเป็นเวอร์ชันที่รายงานบอก** แล้วให้ lockfile เปลี่ยนตาม

   ```bash
   npm install lodash@4.17.21
   ```

2. **ถ้าเลขหลักแรกเปลี่ยน ให้ทดสอบแอปก่อนใช้จริง** เช่นจาก `0.21.1` เป็น `1.15.2` เลขหลักแรกที่เปลี่ยนมักแปลว่าวิธีใช้เปลี่ยนด้วย ให้ AI อ่านบันทึกการเปลี่ยนแปลงของ library ตัวนั้นและแก้โค้ดตาม แล้วลองกดใช้แอปจริง
3. **ถ้าตัวที่มีปัญหาเป็น dependency ของ dependency** อัปเดตตัวที่คุณติดตั้งเองก่อน รุ่นใหม่ของมันมักดึงเวอร์ชันที่แก้แล้วมาให้ ถ้ายังไม่หาย [เอกสารของ npm][npmoverrides] มีช่อง `overrides` ใน `package.json` ไว้บังคับเวอร์ชันของ dependency ของ dependency โดยเฉพาะกรณีที่มีปัญหาความปลอดภัย

   ```json
   {
     "overrides": {
       "minimist": "1.2.8"
     }
   }
   ```

   แล้วรัน `npm install` อีกครั้ง ใส่ได้เฉพาะ `package.json` ที่อยู่บนสุดของโปรเจกต์
4. **ถ้ารายงานบอกว่ายังไม่มีเวอร์ชันที่แก้** ดูว่าแอปใช้ส่วนที่มีปัญหาไหม ถ้าใช้ ลองหา library อื่นที่ทำงานเดียวกันมาแทน
5. **ตรวจซ้ำ**

   ```bash
   npx ai-secure-audit retest
   ```

6. **deploy ใหม่** เซิร์ฟเวอร์ที่รันอยู่ยังใช้เวอร์ชันเก่าจนกว่าจะเอาของใหม่ขึ้นไป

## ดักไว้ล่วงหน้า

- **ตรวจก่อน deploy ทุกครั้ง** ช่องโหว่ใหม่ประกาศทุกวัน แอปที่เมื่อเดือนก่อนตรวจผ่าน วันนี้อาจไม่ผ่าน
- **ให้ AI ติดตั้งด้วยคำสั่ง ไม่ใช่เขียนเลขเวอร์ชันเอง** บอก AI ว่า "ติดตั้ง library ด้วย `npm install` ให้ได้เวอร์ชันล่าสุด ห้ามเขียนเลขเวอร์ชันลง `package.json` เอง"
- **เปิด Dependabot บน GitHub** [Dependabot alerts][dependabot] แจ้งเตือนเมื่อ library ในโปรเจกต์มีช่องโหว่ใหม่ และ [Dependabot security updates][dependabotupdates] เปิด pull request อัปเดตเป็นเวอร์ชันต่ำสุดที่แก้แล้วให้เอง คุณแค่ตรวจแล้วกดรวม
- **commit lockfile เข้า git เสมอ** [เอกสารของ npm][npmlock] บอกว่า lockfile ทำให้ติดตั้งครั้งต่อไปได้ library ชุดเดิมทุกตัว ถ้าไม่มี lockfile เครื่องที่ deploy อาจได้เวอร์ชันต่างจากที่คุณตรวจ

## สิ่งที่การตรวจนี้มองไม่เห็น

- โปรเจกต์ที่ไม่มี lockfile (มีแค่ `package.json`)
- library ที่โหลดจาก CDN ด้วย `<script src="https://...">` ในหน้าเว็บ เพราะไม่อยู่ใน lockfile
- โค้ดของ library ที่ก็อปมาวางในโปรเจกต์ตรง ๆ
- ช่องโหว่ที่ยังไม่มีใครประกาศ
- ว่าแอปเรียกใช้ส่วนที่มีช่องโหว่จริงหรือไม่
- โปรแกรมของระบบบนเซิร์ฟเวอร์ หรือใน Docker image (เป็นเรื่องของข้อ 6)
- โฟลเดอร์ `node_modules/` และไฟล์ที่ git ignore เครื่องมือข้ามไป เพราะ lockfile บอกครบแล้ว

## แหล่งอ้างอิง

เข้าถึงเมื่อ 10 พฤศจิกายน 2569

- [OWASP Top 10:2025][owasp]
- [FIRST: CVSS v3.1 Specification][cvss] §5 Qualitative Severity Rating Scale
- [OSV: A distributed vulnerability database for Open Source][osv]
- [osv-scanner: Supported languages and lockfiles][osvlockfiles]
- [npm Docs: package-lock.json][npmlock]
- [npm Docs: package.json][npmjson]
- [npm Docs: package.json overrides][npmoverrides]
- [npm Docs: npm audit][npmaudit]
- [GitHub Docs: About Dependabot alerts][dependabot]
- [GitHub Docs: Dependabot security updates][dependabotupdates]
- [GitHub Advisory: Prototype Pollution in minimist (GHSA-xvch-5gv4-984h)][ghminimist]
- [GitHub Advisory: Command Injection in lodash (GHSA-35jh-r3h4-6jhm)][ghlodash]

[owasp]: https://top10.owasp.org/2025/
[cvss]: https://www.first.org/cvss/v3.1/specification-document
[osv]: https://osv.dev/
[osvlockfiles]: https://google.github.io/osv-scanner/supported-languages-and-lockfiles/
[npmlock]: https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json
[npmjson]: https://docs.npmjs.com/cli/v10/configuring-npm/package-json
[npmoverrides]: https://docs.npmjs.com/cli/v10/configuring-npm/package-json#overrides
[npmaudit]: https://docs.npmjs.com/cli/v10/commands/npm-audit
[dependabot]: https://docs.github.com/en/code-security/dependabot/dependabot-alerts/about-dependabot-alerts
[dependabotupdates]: https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates
[ghminimist]: https://github.com/advisories/GHSA-xvch-5gv4-984h
[ghlodash]: https://github.com/advisories/GHSA-35jh-r3h4-6jhm
