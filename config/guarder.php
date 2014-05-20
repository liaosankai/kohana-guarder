<?php

defined('SYSPATH') or die('No direct script access.');

return array(
    // 定義角色
    'roles' => array(
        'user' => array(
            // {method}://{directory}/{controller}/{action}
            'allow' => array(
                '',
                '*', // => '*://*/*/*',
                '://',
                '*://*/*/*',
                '*://*/*/zzz',
                '*://*/yyy/zzz',
                '*://xxx/yyy/zzz',
                '*://xxx/yyy/*',
                '*://xxx/*/zzz',
                '*://*/yyy/zzz',
                'xxx', // => *://xxx/*/*
                'yyy/zzz', // => *://*/yyy/zzz
                'xxx/yyy/zzz', // => *://xxx/yyy/zzz
                'yyy/*', // => *://*/yyy/*
                'GET://yyy/*'          // => GET://*/yyy/*
            ),
            'deny' => array(
                'forum/thread/edit'
            )
        ),
        'admin' => array(
            'allow' => array(
                'get://forum',
                'get://forum/thread'
            ),
            'deny' => array(
                'forum/thread/edit'
            )
        )
    ),
    // 定義資源
    'resources' => array(
        'get://home/index' => array(
            'title' => '檢視',
            'visible' => FALSE,
        ),
        'get://home/ooo' => array(
            'title' => '檢視',
            'visible' => FALSE,
        ),
        'get://home/vvv' => array(
            'title' => '檢視',
            'visible' => FALSE,
        ),
        'post://api/Album/*'
    ),
);
