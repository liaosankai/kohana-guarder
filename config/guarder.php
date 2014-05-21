<?php

defined('SYSPATH') or die('No direct script access.');

return array(
    'autoload' => TRUE,
    // 定義角色
    'roles' => array(
        'login' => array(
            'allow' => array(
                'api/news/*',
            //   'api/*/*'
            ),
            'deny' => array(
                //  'get://api/room/index',
                'post://api/news/*',
                'put://api/news/*',
                'get://api/news/index'
            )
        ),
        'admin' => array(
            '*'
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
