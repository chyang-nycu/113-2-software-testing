const test = require('node:test');
const assert = require('assert');
const fs = require('fs');
const util = require('util');

// 模擬文件系統
const realPromisify = util.promisify;
util.promisify = function (fn) {
    if (fn === fs.readFile) {
        return function () {
            return Promise.resolve('用戶1\n用戶2\n用戶3\n用戶4');
        };
    }
    return realPromisify(fn);
};

// 導入要測試的模塊 (在模擬後導入)
const { Application, MailSystem } = require('./main');

// 測試 MailSystem 的 write 方法
test('MailSystem write 方法應生成正確的郵件內容', (t) => {
    const mailSystem = new MailSystem();
    const result = mailSystem.write('測試用戶');
    assert.strictEqual(result, 'Congrats, 測試用戶!');
});

// 測試 MailSystem 的 send 方法
test('MailSystem send 方法應返回成功和失敗結果', (t) => {
    const mailSystem = new MailSystem();

    // 替換 Math.random 確保測試結果可預測
    const originalRandom = Math.random;

    // 測試成功情況
    Math.random = () => 0.8; // > 0.5 返回 true
    const success = mailSystem.send('測試用戶', '內容');
    assert.strictEqual(success, true);

    // 測試失敗情況
    Math.random = () => 0.3; // < 0.5 返回 false
    const failure = mailSystem.send('測試用戶', '內容');
    assert.strictEqual(failure, false);

    // 恢復原始函數
    Math.random = originalRandom;
});

// 測試 Application 的 getNames 方法
test('Application getNames 方法應返回名字列表和空的已選列表', async (t) => {
    const app = new Application();
    const [people, selected] = await app.getNames();

    assert.deepStrictEqual(people, ['用戶1', '用戶2', '用戶3', '用戶4']);
    assert.deepStrictEqual(selected, []);
});

// 測試 Application 構造函數
test('Application 構造函數應初始化應用程序狀態', async (t) => {
    const app = new Application();
    // 等待異步初始化完成
    await new Promise(resolve => setTimeout(resolve, 100));

    assert.deepStrictEqual(app.people, ['用戶1', '用戶2', '用戶3', '用戶4']);
    assert.deepStrictEqual(app.selected, []);
});

// 測試 Application 的 getRandomPerson 方法
test('Application getRandomPerson 方法應返回一個人', (t) => {
    const app = new Application();
    app.people = ['用戶1', '用戶2', '用戶3'];

    // 替換 Math.random 確保測試結果可預測
    const originalRandom = Math.random;
    Math.random = () => 0.1; // 將返回第一個用戶

    const person = app.getRandomPerson();
    assert.strictEqual(person, '用戶1');

    // 恢復原始函數
    Math.random = originalRandom;
});

// 測試 Application 的 selectNextPerson 方法 - 所有人都已選中
test('Application selectNextPerson 當所有人都被選中時應返回null', (t) => {
    const app = new Application();
    app.people = ['用戶1', '用戶2'];
    app.selected = ['用戶1', '用戶2'];

    const result = app.selectNextPerson();
    assert.strictEqual(result, null);
});

// 測試 Application 的 selectNextPerson 方法 - 選擇未選中的人
test('Application selectNextPerson 應選擇未選中的人', (t) => {
    const app = new Application();
    app.people = ['用戶1', '用戶2', '用戶3'];
    app.selected = [];

    // 替換 Math.random 確保測試結果可預測
    const originalRandom = Math.random;
    Math.random = () => 0.1; // 將返回第一個用戶

    const person = app.selectNextPerson();
    assert.strictEqual(person, '用戶1');
    assert.deepStrictEqual(app.selected, ['用戶1']);

    // 恢復原始函數
    Math.random = originalRandom;
});

// 測試 Application 的 selectNextPerson 方法 - 避免重覆選擇
test('Application selectNextPerson 應避免重覆選擇', (t) => {
    const app = new Application();
    app.people = ['用戶1', '用戶2', '用戶3'];
    app.selected = ['用戶1']; // 用戶1已經被選中

    // 替換 Math.random 確保我們先嘗試選擇已選中的人，然後選擇新人
    const originalRandom = Math.random;
    let count = 0;
    Math.random = () => {
        count++;
        return count === 1 ? 0 : 0.4; // 第一次返回用戶1(已選)，第二次返回用戶2
    };

    const person = app.selectNextPerson();
    assert.strictEqual(person, '用戶2');
    assert.deepStrictEqual(app.selected, ['用戶1', '用戶2']);
    assert.strictEqual(count, 2); // 確認Math.random被調用了兩次

    // 恢復原始函數
    Math.random = originalRandom;
});

// 測試 Application 的 notifySelected 方法
test('Application notifySelected 應通知所有選中的人', (t) => {
    const app = new Application();
    app.people = ['用戶1', '用戶2', '用戶3'];
    app.selected = ['用戶1', '用戶2'];

    // 跟蹤方法調用
    let writeCount = 0;
    let sendCount = 0;
    const writtenNames = [];

    // 保存並替換原始方法
    const originalWrite = app.mailSystem.write;
    const originalSend = app.mailSystem.send;

    app.mailSystem.write = (name) => {
        writeCount++;
        writtenNames.push(name);
        return `測試內容 for ${name}`;
    };

    app.mailSystem.send = (name, context) => {
        sendCount++;
        return true;
    };

    app.notifySelected();

    assert.strictEqual(writeCount, 2);
    assert.strictEqual(sendCount, 2);
    assert.deepStrictEqual(writtenNames, ['用戶1', '用戶2']);

    // 恢復原始方法
    app.mailSystem.write = originalWrite;
    app.mailSystem.send = originalSend;
});

// 完整工作流程測試
test('完整工作流程應正常工作', (t) => {
    const app = new Application();
    app.people = ['用戶1', '用戶2', '用戶3', '用戶4'];
    app.selected = [];

    // 控制隨機選擇
    const originalRandom = Math.random;
    let randomIndex = 0;
    const randomValues = [0.1, 0.3, 0.6, 0.9]; // 選擇四個不同的人

    Math.random = () => randomValues[randomIndex++ % randomValues.length];

    // 選擇四個人
    const person1 = app.selectNextPerson();
    const person2 = app.selectNextPerson();
    const person3 = app.selectNextPerson();
    const person4 = app.selectNextPerson();

    // 驗證每個人都被選中了
    assert.strictEqual(app.selected.length, 4);
    assert.ok(app.selected.includes(person1));
    assert.ok(app.selected.includes(person2));
    assert.ok(app.selected.includes(person3));
    assert.ok(app.selected.includes(person4));

    // 嘗試再次選擇（所有人都已選中）
    const noMorePerson = app.selectNextPerson();
    assert.strictEqual(noMorePerson, null);

    // 測試通知功能
    let writeCount = 0;
    let sendCount = 0;

    app.mailSystem.write = () => {
        writeCount++;
        return "測試內容";
    };

    app.mailSystem.send = () => {
        sendCount++;
        return true;
    };

    app.notifySelected();

    assert.strictEqual(writeCount, 4);
    assert.strictEqual(sendCount, 4);

    // 恢復原始函數
    Math.random = originalRandom;
});

// 測試後恢復原始函數
test.after(() => {
    util.promisify = realPromisify;
});