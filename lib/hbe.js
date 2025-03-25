(() => {
  'use strict';

  const cryptoObj = window.crypto || window.msCrypto;
  const storage = window.localStorage;

  const storageName = 'hexo-blog-encrypt:#' + window.location.pathname;
  const keySalt = textToArray('hexo-blog-encrypt的作者们都是大帅比!');
  const ivSalt = textToArray('hexo-blog-encrypt是地表最强Hexo加密插件!');

  // As we can't detect the wrong password with AES-CBC,
  // so adding an empty div and check it when decrption.
  const knownPrefix = "<hbe-prefix></hbe-prefix>";

  const mainElement = document.getElementById('hexo-blog-encrypt');
  const wrongPassMessage = mainElement.dataset['wpm'];
  const wrongHashMessage = mainElement.dataset['whm'];
  const dataElement = mainElement.getElementsByTagName('script')['hbeData'];
  const encryptedData = dataElement.innerText;
  const HmacDigist = dataElement.dataset['hmacdigest'];

  function hexToArray(s) {
    return new Uint8Array(s.match(/[\da-f]{2}/gi).map((h => {
      return parseInt(h, 16);
    })));
  }

  function textToArray(s) {
    var i = s.length;
    var n = 0;
    var ba = new Array()

    for (var j = 0; j < i;) {
      var c = s.codePointAt(j);
      if (c < 128) {
        ba[n++] = c;
        j++;
      } else if ((c > 127) && (c < 2048)) {
        ba[n++] = (c >> 6) | 192;
        ba[n++] = (c & 63) | 128;
        j++;
      } else if ((c > 2047) && (c < 65536)) {
        ba[n++] = (c >> 12) | 224;
        ba[n++] = ((c >> 6) & 63) | 128;
        ba[n++] = (c & 63) | 128;
        j++;
      } else {
        ba[n++] = (c >> 18) | 240;
        ba[n++] = ((c >> 12) & 63) | 128;
        ba[n++] = ((c >> 6) & 63) | 128;
        ba[n++] = (c & 63) | 128;
        j += 2;
      }
    }
    return new Uint8Array(ba);
  }

  function arrayBufferToHex(arrayBuffer) {
    if (typeof arrayBuffer !== 'object' || arrayBuffer === null || typeof arrayBuffer.byteLength !== 'number') {
      throw new TypeError('Expected input to be an ArrayBuffer')
    }

    var view = new Uint8Array(arrayBuffer)
    var result = ''
    var value

    for (var i = 0; i < view.length; i++) {
      value = view[i].toString(16)
      result += (value.length === 1 ? '0' + value : value)
    }

    return result
  }

  async function getExecutableScript(oldElem) {
    let out = document.createElement('script');
    const attList = ['type', 'text', 'src', 'crossorigin', 'defer', 'referrerpolicy'];
    attList.forEach((att) => {
      if (oldElem[att])
        out[att] = oldElem[att];
    })

    return out;
  }

  async function convertHTMLToElement(content) {
    let out = document.createElement('div');
    out.innerHTML = content;
    out.querySelectorAll('script').forEach(async (elem) => {
      elem.replaceWith(await getExecutableScript(elem));
    });

    return out;
  }

  function getKeyMaterial(password) {
    let encoder = new TextEncoder();
    return cryptoObj.subtle.importKey(
      'raw',
      encoder.encode(password),
      {
        'name': 'PBKDF2',
      },
      false,
      [
        'deriveKey',
        'deriveBits',
      ]
    );
  }

  function getHmacKey(keyMaterial) {
    return cryptoObj.subtle.deriveKey({
      'name': 'PBKDF2',
      'hash': 'SHA-256',
      'salt': keySalt.buffer,
      'iterations': 1024
    }, keyMaterial, {
      'name': 'HMAC',
      'hash': 'SHA-256',
      'length': 256,
    }, true, [
      'verify',
    ]);
  }

  function getDecryptKey(keyMaterial) {
    return cryptoObj.subtle.deriveKey({
      'name': 'PBKDF2',
      'hash': 'SHA-256',
      'salt': keySalt.buffer,
      'iterations': 1024,
    }, keyMaterial, {
      'name': 'AES-CBC',
      'length': 256,
    }, true, [
      'decrypt',
    ]);
  }

  function getIv(keyMaterial) {
    return cryptoObj.subtle.deriveBits({
      'name': 'PBKDF2',
      'hash': 'SHA-256',
      'salt': ivSalt.buffer,
      'iterations': 512,
    }, keyMaterial, 16 * 8);
  }

  async function verifyContent(key, content) {
    const encoder = new TextEncoder();
    const encoded = encoder.encode(content);

    let signature = hexToArray(HmacDigist);

    const result = await cryptoObj.subtle.verify({
      'name': 'HMAC',
      'hash': 'SHA-256',
    }, key, signature, encoded);
    console.log(`Verification result: ${result}`);
    if (!result) {
      alert(wrongHashMessage);
      console.log(`${wrongHashMessage}, got `, signature, ` but proved wrong.`);
    }
    return result;
  }

  async function decrypt(decryptKey, iv, hmacKey) {
    let typedArray = hexToArray(encryptedData);

    const result = await cryptoObj.subtle.decrypt({
      'name': 'AES-CBC',
      'iv': iv,
    }, decryptKey, typedArray.buffer).then(async (result) => {
      const decoder = new TextDecoder();
      const decoded = decoder.decode(result);

      // check the prefix, if not then we can sure here is wrong password.
      if (!decoded.startsWith(knownPrefix)) {
        throw "Decode successfully but not start with KnownPrefix.";
      }

      const hideButton = document.createElement('button');
      hideButton.textContent = 'Encrypt again';
      hideButton.type = 'button';
      hideButton.classList.add("hbe-button");
      hideButton.addEventListener('click', () => {
        window.localStorage.removeItem(storageName);
        window.location.reload();
      });

      document.getElementById('hexo-blog-encrypt').style.display = 'inline';
      document.getElementById('hexo-blog-encrypt').innerHTML = '';
      document.getElementById('hexo-blog-encrypt').appendChild(await convertHTMLToElement(decoded));
      document.getElementById('hexo-blog-encrypt').appendChild(hideButton);

      // support html5 lazyload functionality.
      document.querySelectorAll('img').forEach((elem) => {
        if (elem.getAttribute("data-src") && !elem.src) {
          elem.src = elem.getAttribute('data-src');
        }
      });

      // support theme-next refresh
      window.NexT && NexT.boot && typeof NexT.boot.refresh === 'function' && NexT.boot.refresh();

      // TOC part
      var tocDiv = document.getElementById("toc-div");
      if (tocDiv) {
        tocDiv.style.display = 'inline';
      }

      var tocDivs = document.getElementsByClassName('toc-div-class');
      if (tocDivs && tocDivs.length > 0) {
        for (var idx = 0; idx < tocDivs.length; idx++) {
          tocDivs[idx].style.display = 'inline';
        }
      }

      // trigger event
      var event = new Event('hexo-blog-decrypt');
      window.dispatchEvent(event);

      return await verifyContent(hmacKey, decoded);
    }).catch((e) => {
      alert(wrongPassMessage);
      console.log(e);
      return false;
    });

    return result;

  }

  function hbeLoader() {

    const oldStorageData = JSON.parse(storage.getItem(storageName));

    if (oldStorageData) {
      console.log(`Password got from localStorage(${storageName}): `, oldStorageData);

      const sIv = hexToArray(oldStorageData.iv).buffer;
      const sDk = oldStorageData.dk;
      const sHmk = oldStorageData.hmk;

      cryptoObj.subtle.importKey('jwk', sDk, {
        'name': 'AES-CBC',
        'length': 256,
      }, true, [
        'decrypt',
      ]).then((dkCK) => {
        cryptoObj.subtle.importKey('jwk', sHmk, {
          'name': 'HMAC',
          'hash': 'SHA-256',
          'length': 256,
        }, true, [
          'verify',
        ]).then((hmkCK) => {
          decrypt(dkCK, sIv, hmkCK).then((result) => {
            if (!result) {
              storage.removeItem(storageName);
            }
          });
        });
      });
    }

    mainElement.addEventListener('keydown', async (event) => {
      if (event.isComposing || event.keyCode === 13) {
        const password = document.getElementById('hbePass').value;
        const keyMaterial = await getKeyMaterial(password);
        const hmacKey = await getHmacKey(keyMaterial);
        const decryptKey = await getDecryptKey(keyMaterial);
        const iv = await getIv(keyMaterial);

        // 添加提交按钮 - 适配移动端
        const passwordInput = document.getElementById('hbePass');
        if (passwordInput) {
          // 创建提交按钮
          const submitButton = document.createElement('button');
          submitButton.textContent = '提交密码';
          submitButton.type = 'button';
          submitButton.className = 'hbe-button';
          submitButton.style.cssText = 'margin-top: 10px; width: 60%; text-align: center; text-indent: 0;';

          // 将按钮插入到密码框的父元素后面
          const inputContainer = passwordInput.closest('.hbe-input');
          if (inputContainer) {
            inputContainer.insertAdjacentElement('afterend', submitButton);
          }

          // 密码预处理函数 - 处理可能的编码问题
          function sanitizePassword(password) {
            // 移除前后空格和不可见字符
            return password.trim().replace(/\s+/g, '');
          }

          // 为按钮添加点击事件 - 增强版
          submitButton.addEventListener('click', function (e) {
            // 阻止事件冒泡
            e.stopPropagation();
            e.preventDefault();

            // 提供视觉反馈
            submitButton.textContent = '处理中...';
            submitButton.disabled = true;

            // 使用setTimeout确保UI更新
            setTimeout(async function () {
              try {
                console.log("按钮被点击，开始处理密码");
                // 获取并清理密码
                let password = document.getElementById('hbePass').value;
                password = sanitizePassword(password);
                console.log("处理后的密码长度:", password.length);

                // 检查Web Crypto API可用性
                if (!cryptoObj || !cryptoObj.subtle) {
                  alert("您的浏览器不支持Web Crypto API，请尝试更新浏览器");
                  submitButton.textContent = '提交密码';
                  submitButton.disabled = false;
                  return;
                }

                // 使用Promise.all优化并行操作
                try {
                  const keyMaterial = await getKeyMaterial(password);

                  // 并行处理密钥生成
                  const [hmacKey, decryptKey, iv] = await Promise.all([
                    getHmacKey(keyMaterial),
                    getDecryptKey(keyMaterial),
                    getIv(keyMaterial)
                  ]);

                  console.log("密钥生成成功，开始解密");

                  // 设置超时保护
                  const timeoutPromise = new Promise((_, reject) => {
                    setTimeout(() => reject(new Error("解密操作超时")), 10000);
                  });

                  // 使用Promise.race防止操作卡死
                  const decryptPromise = decrypt(decryptKey, iv, hmacKey);
                  const result = await Promise.race([decryptPromise, timeoutPromise]);

                  console.log(`解密结果: ${result}`);
                  if (result) {
                    // 并行处理密钥导出
                    const [dk, hmk] = await Promise.all([
                      cryptoObj.subtle.exportKey('jwk', decryptKey),
                      cryptoObj.subtle.exportKey('jwk', hmacKey)
                    ]);

                    const newStorageData = {
                      'dk': dk,
                      'iv': arrayBufferToHex(iv),
                      'hmk': hmk,
                    };
                    storage.setItem(storageName, JSON.stringify(newStorageData));
                  } else {
                    // 恢复按钮状态
                    submitButton.textContent = '提交密码';
                    submitButton.disabled = false;
                  }
                } catch (error) {
                  console.error("解密过程出错:", error);
                  alert("解密失败: " + (error.message || "未知错误"));
                  submitButton.textContent = '提交密码';
                  submitButton.disabled = false;
                }
              } catch (error) {
                console.error("整体处理出错:", error);
                alert("处理过程出错: " + (error.message || "未知错误"));
                submitButton.textContent = '提交密码';
                submitButton.disabled = false;
              }
            }, 100);

          });

          // 添加触摸事件支持
          submitButton.addEventListener('touchend', function (e) {
            e.preventDefault();
            this.click();
          });

          // 添加密码输入优化
          passwordInput.addEventListener('input', function () {
            // 移除输入中可能的不可见字符
            const cleanValue = this.value.replace(/[\u200B-\u200D\uFEFF]/g, '');
            if (cleanValue !== this.value) {
              this.value = cleanValue;
            }
          });
        }

        decrypt(decryptKey, iv, hmacKey).then((result) => {
          console.log(`Decrypt result: ${result}`);
          if (result) {
            cryptoObj.subtle.exportKey('jwk', decryptKey).then((dk) => {
              cryptoObj.subtle.exportKey('jwk', hmacKey).then((hmk) => {
                const newStorageData = {
                  'dk': dk,
                  'iv': arrayBufferToHex(iv),
                  'hmk': hmk,
                };
                storage.setItem(storageName, JSON.stringify(newStorageData));
              });
            });
          }
        });
      }
    });
  }

  hbeLoader();

})();
