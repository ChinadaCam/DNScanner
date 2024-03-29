
 <h1 align="center"> DNScanner 1.0x </h1>
<h2 align="center"  > Easiest way to scan domains via cli </h2>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]





<!-- TABLE OF CONTENTS -->
## Table of Contents

* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
  * [Usage Examples](#usage-examples)
* [Roadmap](#roadmap)
* [License](#license)
* [Contact](#contact)




<!-- ABOUT THE PROJECT -->
## About The Project

Automate your Domain scan like a pro!!
This is a tool that started being developed as a module for another OSINT/Pentest tool (Still in development) and  I decided to make it as a solo build too.
It's still in early development but getting more and more features, you can export the output to a txt file and decide what information you want it to have.
Do a simple   ```py3
     start.py -d example.com -A 
              ``` to get a scan with all the features.
  

Current features:
 * Get IPv4 and IPv6.
 * Get MX/NS/CN Records.
 * Whois.
 * Subdomains discovery.
 * Output to text file.
 * URL Status
 * ICMP Checker

To be added:
 * Report to pdf
 * Get wildcard
 * Geolocation


<!-- GETTING STARTED -->
## Getting Started
The project is under construction, if something wrong happens please report it to [open issues](https://github.com/ChinadaCam/DNScanner/issues).


### Prerequisites

Python3 & pip



### Installation

1. Clone the repo
```sh
git clone https://github.com/ChinadaCam/DNScanner.git
```
2, Install requirements

```sh
python3 pip install -r requirements.txt
```
3. Run it
```sh
python3 start.py -d example.com
```

### Usage Examples

   1. Simple Usage | 
   ``` py  
   python3  start.py -d example.com 
```
   2. Define a directory to output |
   ```py 
    python3  start.py -d example.com -O -D=NameOfDirectory
   ```
   3. Get subdomains | 
   ```py 
   python3 start.py -d example.com -cS
   ```


Output for the following command:
  ``` py  
  python3 start.py -d google.com -ns -mx -W 
  ```
 

![Screenshot_1](https://user-images.githubusercontent.com/20567276/161407610-83a9ca58-08a7-4799-a4bc-b470d0899b1e.png)



<!-- Suggestions and Issues -->
## Roadmap

Go to [DNScanner Board](https://github.com/ChinadaCam/DNScanner/projects/1)


[ChinadaCam](https://github.com/ChinadaCam)


See the [open issues](https://github.com/ChinadaCam/DNScanner/issues) for a list of proposed features (and known issues).
Give us some [suggestions](https://github.com/ChinadaCam/DNScanner/labels/suggestions)



<!-- LICENSE -->
## License

Distributed under the GPL-3.0 License . See `LICENSE` for more information.

<!-- CONTACT -->
## Contact
[![LinkedIn][linkedin-shield]][linkedin-url]  <a href="https://twitter.com/fuckingfaustino">
    <img alt="Twitter: fuckingfaustino" src="https://img.shields.io/twitter/follow/fuckingfaustino.svg?style=social" target="_blank" />
  </a>

Tiago Faustino - tiagfaustino@gmail.com
Discord: fลuร†เиѳ#7797
 
Project Link: [https://github.com/ChinadaCam/DNScanner](https://github.com/ChinadaCam/DNScanner)
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/H2H27JW0K)

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/ChinadaCam/DNScanner.svg?style=flat-square
[contributors-url]: https://github.com/ChinadaCam/DNScanner/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/ChinadaCam/DNScanner.svg?style=flat-square
[forks-url]: https://github.com/ChinadaCam/DNScanner/network/members
[stars-shield]: https://img.shields.io/github/stars/ChinadaCam/DNScanner.svg?style=flat-square
[stars-url]: https://github.com/ChinadaCam/DNScanner/stargazers
[issues-shield]: https://img.shields.io/github/issues/ChinadaCam/DNScanner.svg?style=flat-square
[issues-url]: https://github.com/ChinadaCam/DNScanner/issues
[license-shield]: https://img.shields.io/github/license/ChinadaCam/DNScanner.svg?style=flat-square
[license-url]: https://github.com/ChinadaCam/DNScanner/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=flat-square&logo=linkedin&colorB=555
[linkedin-url]: https://www.linkedin.com/in/tiago-faustino-b07523166/
 
 
