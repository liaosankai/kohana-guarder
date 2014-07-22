<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * Kohana 權限衛兵
 * 
 * 用來檢查指定角色是否有請求控制器動作的權限
 */
class Kohana_Guarder
{

    /**
     * 萬用字元符號常數
     * 
     * @var string
     */
    const WILDCARD = '*';

    /**
     * 表示支援 POST 和 GET 的 method
     * 
     * @var string
     */
    const ACTION_METHOD = 'ACTION';

    /**
     * 表示所有 method
     * 
     * @var string
     */
    const ALL_METHOD = 'ALL';

    /**
     * 衛兵類別實例
     * 
     * @var Guarder
     */
    static $instance;

    /**
     * 衛兵實例
     * 
     * @access	public
     * @return	Guarder
     */
    public static function instance(array $config = array())
    {
        if (self::$instance === NULL) {
            self::$instance = new Guarder($config);
        }

        return self::$instance;
    }

    /**
     * 資源資訊表
     * 
     * @access protected
     * @var array
     */
    protected $_resources;

    /**
     * 角色權限表
     * 
     * @access protected
     * @var array
     */
    protected $_roles = array();

    /**
     * 設定檔
     * 
     * @access protected
     * @var array
     */
    protected $_config = array();

    /**
     * 當前請求器
     * 
     * @access protected
     * @var array
     */
    protected $_request;

    /**
     * 建構子
     * 
     * @access	public
     * @return	void
     */
    public function __construct(array $config = array())
    {
        // 讀取設定檔
        $this->_config = Arr::merge(Kohana::$config->load('guarder')->as_array(), $config);

        // 設置基本環境
        $this->_setup();

        // 設定當前請求器
        $this->_request = Request::current();
    }

    /**
     * 檢查角色是否可以通行
     * 
     * @param string|array|Model_User $target 角色或使用者
     * @return boolean 
     */
    public function is_pass($target = array(), $method = NULL, $directory = NULL, $controller = NULL, $action = NULL)
    {
        // 取得欲檢查的角色(預設都會有一個 guest 的角色)
        $roles = array('guest');
        if ($target instanceof Model_User) {
            foreach ($target->roles->find_all() as $role) {
                $roles[] = $role->name;
            }
        } else {
            $roles = (gettype($target) === 'array') ? array_merge($roles, $target) : array_merge($roles, array($target));
        }

        $mdca = array(
            'method' => ($method) ? $method : $this->_request->method(),
            'directory' => ($directory) ? $directory : (($this->_request->directory() === "") ? 'default' : $this->_request->directory()),
            'controller' => ($controller) ? $controller : $this->_request->controller(),
            'action' => ($action) ? $action : $this->_request->action(),
        );



        // 記錄各角色的 pass 狀態
        $roles_pass = array();
        foreach (array_unique($roles) as $name) {
            // 取得角色權限表
            $authorities = Arr::get($this->_roles, $name, array());
            // 允許的狀態
            $allow_pass = $this->_is_match(Arr::get($authorities, 'allow', array()), $mdca);
            // 禁止的狀態
            $deny_pass = $this->_is_match(Arr::get($authorities, 'deny', array()), $mdca);

            // 記錄各角色的執行權限
            $roles_pass[$name] = ($allow_pass === TRUE AND $deny_pass === FALSE);
        }


        // 有一種角色通過，就算通過
        return in_array(TRUE, $roles_pass, TRUE);
    }

    /**
     * 設定單一角色權限
     * 
     * @param type $role_name 角色名稱
     * @param type $authorities 權限表
     */
    public function set_role($role_name, $authorities)
    {
        foreach ($authorities as $key => $authority) {
            if (is_string($authority)) {
                $authorities['allow'][] = $authority;
                unset($authorities[$key]);
            }
        }
        $this->_roles[$role_name] = $authorities;
        return $this;
    }

    /**
     * 設定多個角色權限
     * 
     * @access	public
     * @param array $roles 角色權限陣列
     * @return	$this
     */
    public function set_roles(array $roles = array())
    {
        foreach ($roles as $name => $authority) {
            $this->set_role($name, $authority);
        }

        return $this;
    }

    /**
     * Get role
     * 
     * @access	public
     * @return	Deputy_Role
     */
    public function get_role($name, $default = FALSE)
    {
        if (isset($this->_roles[$name])) {
            return $this->_roles[$name];
        } else {
            return $default;
        }
    }

    /**
     * Get roles
     * 
     * @access	public
     * @return	array
     */
    public function get_roles()
    {
        return $this->_roles;
    }

    /**
     * 配對權限字串
     * 
     * @param array $list 權限字串陣列
     * @return boolean
     */
    private function _is_match(array $list = array(), $mdca = array())
    {
        $m = Arr::get($mdca, 'method');
        $d = Arr::get($mdca, 'directory');
        $c = Arr::get($mdca, 'controller');
        $a = Arr::get($mdca, 'action');

        // 檢查器
        $checker = array();
        $match = FALSE;
        foreach ($list as $uri) {
            $authority = $this->_parse_uri($uri);
            // 檢查 method 部分
            $am = Arr::get($authority, 'method');

            switch ($am) {
                case Guarder::ALL_METHOD:
                    $checker['method'] = TRUE;
                    break;
                case Guarder::ACTION_METHOD:
                    $checker['method'] = in_array($m, array(Request::POST, Request::GET));
                    break;
                default:
                    $checker['method'] = !strcasecmp($m, $am);
                    break;
            }
            // 檢查 directory 部分
            $checker['directory'] = (Arr::get($authority, 'directory') === TRUE) ? TRUE : !strcasecmp($d, Arr::get($authority, 'directory'));
            // 檢查 controller 部分;
            $checker['controller'] = (Arr::get($authority, 'controller') === TRUE) ? TRUE : !strcasecmp($c, Arr::get($authority, 'controller'));
            // 檢查 action 部分
            $checker['action'] = (Arr::get($authority, 'action') === TRUE) ? TRUE : !strcasecmp($a, Arr::get($authority, 'action'));
            // 取得結果( 要全為 TRUE )

            $match = (count(array_unique($checker)) === 1) ? current($checker) : FALSE;
            if ($match) {
                break;
            }
        }
        return $match;
    }

    /**
     * 剖析權限字串
     * 
     * @param string $uri 字串結構為 {method}://{directory}/{controller}/{action}
     * @return array
     */
    private function _parse_uri($uri = "")
    {
        // 去頭尾空白，並移除字尾的斜線，和字頭的 ://
        $url = ltrim(rtrim(trim($uri), '/'), '://');
        // 剖析路徑
        $parse_url = parse_url($url);


        // 取得 method 部分，若沒設定，使用 Guarder::ACTION 為預設
        $method = strtoupper(Arr::get($parse_url, 'scheme', Guarder::ACTION_METHOD));

        $checker = explode('://', Arr::get($parse_url, 'path'));
        $method = (Arr::get($checker, 0) == '*') ? Guarder::WILDCARD : $method;

        // 重組 path 部分 (取得 :// 後面的字串)
        $path = (stripos($url, '://') === FALSE) ? $url : substr($url, stripos($url, '://') + 3);
        $path_fragment = array_filter(explode("/", $path));
        $count = count($path_fragment);
        switch ($count) {
            case 1:
                $directory = Guarder::WILDCARD;
                $controller = Arr::get($path_fragment, 0, FALSE);
                $action = Guarder::WILDCARD;
                break;
            case 2:
                $directory = Guarder::WILDCARD;
                $controller = Arr::get($path_fragment, 0, FALSE);
                $action = Arr::get($path_fragment, 1, FALSE);
                break;
            case 3:
                $directory = Arr::get($path_fragment, 0, 'default');
                $controller = Arr::get($path_fragment, 1, FALSE);
                $action = Arr::get($path_fragment, 2, FALSE);
                break;
            default:
                $directory = NULL;
                $controller = NULL;
                $action = NULL;
        }
        if (isset($directory) AND isset($controller) AND isset($action)) {
            return array(
                // 'uri' => $uri,
                // 'map' => "{$method}://{$directory}/{$controller}/{$action}",
                'method' => ($method === Guarder::WILDCARD) ? Guarder::ALL_METHOD : $method,
                'directory' => ($directory === Guarder::WILDCARD) ? TRUE : $directory,
                'controller' => ($controller === Guarder::WILDCARD) ? TRUE : $controller,
                'action' => ($action === Guarder::WILDCARD) ? TRUE : $action,
            );
        } else {
            array();
        }
    }

    /**
     * 設置角色權限
     * 
     * @access	public
     * @return	void
     */
    private function _setup()
    {
        foreach (Arr::get($this->_config, 'roles', array()) as $role_name => $authorities) {
            if (!Arr::get($this->_config, 'autoload')) {
                break;
            }
            // 若沒有指定 allow 的，都轉移至 allow 中
            foreach ($authorities as $key => $authority) {
                if (is_string($authority)) {
                    $authorities['allow'][] = $authority;
                    unset($authorities[$key]);
                }
            }
            $this->_roles[$role_name] = $authorities;
        }
    }

}
