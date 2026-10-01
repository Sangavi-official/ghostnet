# Reference check — 26 Sept draft (`GhostNet_IEEE_Paper_updated (1).docx`)

Checked 30 Sept 2026 against Crossref, arXiv, Semantic Scholar, the publishers'
pages, and the source PDFs in `documents/`.

**Result: all 16 references exist. None is fabricated.** But 7 entries have
wrong or missing details, 4 in-text citations point to the wrong paper, and 3
sources the text relies on are missing from the list.

## 1. Each reference

| Old # | Exists? | What was wrong | What it can support |
|---|---|---|---|
| [1] Yoon et al., DESOLATER | ✅ | Author "J. Cho" is "J.-H. Cho"; DOI missing | DRL that jointly allocates resources and deploys MTD |
| [2] Armis white paper | ✅ (PDF in `documents/`) | Subtitle shortened | Security risk of unmanaged medical/IoT devices |
| [3] Applebaum et al., ACSAC 2016 | ✅ | Stray "[R1]" marker; pages 363–373 missing. **The text uses [3] for the "Clarity" report — wrong paper** | CALDERA's origin: automated red-team emulation |
| [4] Holm & Helgeson, HICSS 2026 | ✅ | **The text uses [4] for MITRE ATT&CK — wrong paper** | Empirical test of 4 emulators over 1,700 h: CALDERA discovered 27% of machines and compromised 7% |
| [5] Yulianto et al. | ✅ | Year is **2025** (vol. 3), not 2024. **The text uses [5] for CALDERA — wrong paper** | A method for building red-team exercises on ATT&CK |
| [6] NIST NVD | ✅ | Access date missing; never cited in the text | Source of the CVE feed |
| [7] Schulman et al., PPO | ✅ | Never cited in the text | The PPO algorithm |
| [8] Raffin et al., SB3 | ✅ | — | Stable-Baselines3 |
| [9] Huertas Celdrán et al. | ✅ | Cited as a 2022 arXiv preprint; **now published** in IEEE TIFS 2024 | RL + behavioural fingerprinting to pick MTD against zero-day attacks in IoT |
| [10] Feng et al., CyberForce | ✅ | Volume, pages, DOI missing | Federated RL that learns which MTD to apply against zero-day attacks in IoT |
| [11] Eghtesad et al., GameSec 2020 | ✅ | DOI missing. **Also cited for "Gymnasium" — wrong paper** | Adversarial DRL / game-theoretic adaptive MTD |
| [12] Zhang et al., ID-HAM | ✅ | Volume, pages, DOI missing | DRL host-address mutation against reconnaissance, keeping existing connections alive |
| [13] D3O-IIoT | ✅ | **No authors**; volume and article number missing | Dueling-DQN orchestration of deception incl. MTD in industrial IoT |
| [14] Torquato & Vieira | ✅ | DOI missing | Cloud MTD mapping study (95 papers): multi-layer MTD and MTD evaluation frameworks are open problems |
| [15] Park et al., Ghost-MTD | ✅ | DOI missing | Protocol mutation with a pre-shared one-time bit sequence; decoy-hole for attackers; 3.28–4.97% overhead |
| [16] Alavizadeh et al. | ✅ | **Venue missing; year is 2022**, not 2020 | Shuffle/diversity/redundancy MTD judged by security and economic metrics, incl. an e-health cloud model |

## 2. Missing from the list (the text relies on them)

- **Claroty Team82 report.** The draft calls it "Clarity". The PDF is
  `documents/state-of-cps-security-healthcare-2023.pdf`. It gives the exact
  number the introduction needs: **14% of connected medical devices run an
  unsupported or end-of-life OS** (the draft only says "a large proportion").
- **MITRE ATT&CK** (Strom et al., design and philosophy report).
- **Gymnasium** (Towers et al.).

## 3. In-text fixes for the 26 Sept draft

| Where | Now says | Should cite |
|---|---|---|
| Intro and II-B, "unsupported operating systems [2], [3]" | [3] = Applebaum | Armis + **Claroty** |
| II-D, "MITRE ATT&CK ... [4]" | [4] = Holm | **Strom et al.** |
| II-D, "CALDERA ... [5]" | [5] = Yulianto | **Applebaum et al.** |
| IV-D, "custom Gymnasium environment [11]" | [11] = Eghtesad | **Towers et al.** |
| III-B / VI-A threat feeds | not cited | **NVD** |
| IV-D "Proximal Policy Optimization" | not cited | **Schulman et al.** |

## 4. Corrected entries (IEEE style)

Final numbers depend on the order of first citation in the rewritten paper.

- S. Yoon, J.-H. Cho, D. S. Kim, T. J. Moore, F. Free-Nelson, and H. Lim, "DESOLATER: Deep reinforcement learning-based resource allocation and moving target defense deployment framework," *IEEE Access*, vol. 9, pp. 70700–70714, 2021, doi: 10.1109/ACCESS.2021.3076599.
- Armis, "Medical and IoT device security for healthcare: Managing risk and ensuring patient safety with 21st century healthcare," White Paper, Armis, Inc., 2024.
- Claroty Team82, "State of CPS security report: Healthcare 2023," Claroty, 2023.
- B. E. Strom, A. Applebaum, D. P. Miller, K. C. Nickels, A. G. Pennington, and C. B. Thomas, "MITRE ATT&CK: Design and philosophy," The MITRE Corporation, Tech. Rep., Mar. 2020 (first published Jul. 2018).
- A. Applebaum, D. Miller, B. Strom, C. Korban, and R. Wolf, "Intelligent, automated red team emulation," in *Proc. 32nd Annu. Conf. Computer Security Applications (ACSAC)*, 2016, pp. 363–373, doi: 10.1145/2991079.2991111.
- H. Holm and L. Helgeson, "An empirical study of automated adversary emulators," in *Proc. 59th Hawaii Int. Conf. System Sciences (HICSS)*, 2026, doi: 10.24251/HICSS.2026.834.
- S. Yulianto, B. Soewito, F. L. Gaol, and A. Kurniawan, "Enhancing cybersecurity resilience through advanced red-teaming exercises and MITRE ATT&CK framework integration: A paradigm shift in cybersecurity assessment," *Cyber Security and Applications*, vol. 3, Art. no. 100077, 2025, doi: 10.1016/j.csa.2024.100077.
- National Institute of Standards and Technology, "National Vulnerability Database." [Online]. Available: https://nvd.nist.gov/ (accessed Sep. 2026).
- J. Schulman, F. Wolski, P. Dhariwal, A. Radford, and O. Klimov, "Proximal policy optimization algorithms," arXiv:1707.06347, 2017.
- A. Raffin, A. Hill, A. Gleave, A. Kanervisto, M. Ernestus, and N. Dormann, "Stable-Baselines3: Reliable reinforcement learning implementations," *J. Mach. Learn. Res.*, vol. 22, no. 268, pp. 1–8, 2021.
- M. Towers *et al.*, "Gymnasium: A standard interface for reinforcement learning environments," in *Advances in Neural Information Processing Systems 38*, 2025, pp. 163114–163129.
- A. Huertas Celdrán, P. M. Sánchez Sánchez, J. von der Assen, T. Schenk, G. Bovet, G. Martínez Pérez, and B. Stiller, "RL and fingerprinting to select moving target defense mechanisms for zero-day attacks in IoT," *IEEE Trans. Inf. Forensics Security*, vol. 19, pp. 5520–5529, 2024, doi: 10.1109/TIFS.2024.3402055.
- C. Feng, A. Huertas Celdrán, P. M. Sánchez Sánchez, J. Kreischer, J. von der Assen, G. Bovet, G. Martínez Pérez, and B. Stiller, "CyberForce: A federated reinforcement learning framework for malware mitigation," *IEEE Trans. Dependable Secure Comput.*, vol. 22, no. 4, pp. 4398–4411, 2025, doi: 10.1109/TDSC.2025.3547005.
- T. Eghtesad, Y. Vorobeychik, and A. Laszka, "Adversarial deep reinforcement learning based adaptive moving target defense," in *Decision and Game Theory for Security (GameSec 2020)*, Lecture Notes in Computer Science. Cham, Switzerland: Springer, 2020, pp. 58–79, doi: 10.1007/978-3-030-64793-3_4.
- T. Zhang, C. Xu, J. Shen, X. Kuang, and L. A. Grieco, "How to disturb network reconnaissance: A moving target defense approach based on deep reinforcement learning," *IEEE Trans. Inf. Forensics Security*, vol. 18, pp. 5735–5748, 2023, doi: 10.1109/TIFS.2023.3314219.
- U. Wushishi, A. Hussain, M. I. Khalid, N. Hussain, M. Jamjoom, and Z. Ullah, "D3O-IIoT: Deep reinforcement learning-driven dynamic deception orchestration for industrial IoT security," *Sci. Rep.*, vol. 16, Art. no. 2389, 2025 (published online Dec. 21, 2025), doi: 10.1038/s41598-025-33426-4.
- M. Torquato and M. Vieira, "Moving target defense in cloud computing: A systematic mapping study," *Computers & Security*, vol. 92, Art. no. 101742, 2020, doi: 10.1016/j.cose.2020.101742.
- J.-G. Park, Y. Lee, K.-W. Kang, S.-H. Lee, and K.-W. Park, "Ghost-MTD: Moving target defense via protocol mutation for mission-critical cloud systems," *Energies*, vol. 13, no. 8, Art. no. 1883, 2020, doi: 10.3390/en13081883.
- H. Alavizadeh, S. Aref, D. S. Kim, and J. Jang-Jaccard, "Evaluating the security and economic effects of moving target defense techniques on the cloud," *IEEE Trans. Emerg. Topics Comput.*, vol. 10, no. 4, pp. 1772–1788, 2022, doi: 10.1109/TETC.2022.3155272.

## 5. Still to do

- New references needed by the rewrite (DQN, A2C, domain randomization, HMAC,
  MQTT) must go through the same check before they are cited.
- Someone should open each DOI once in a browser as a final human check.
