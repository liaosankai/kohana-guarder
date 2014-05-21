<?php

defined('SYSPATH') or die('No direct script access.');

/**
 * Kohana 權限衛兵
 * 
 * 用來檢查指定角色是否有請求控制器動作的權限
 */
class Kohana_Guarder {

    /**
     * 萬用字元符號常數
     * 
     * @var string
     */
    const WILDCARD = '*';

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
        // Create root resource
        $this->_resources = new Deputy_Resource;

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
    public function is_pass($target = array())
    {
        if ($target instanceof Model_User) {
            foreach ($target->roles()->find_all() as $role) {
                $roles[] = $role->name;
            }
        } else {
            $roles = (gettype($target) === 'string') ? array($target) : $target;
        }
        $roles = is_array($roles) ? $roles : array();
        $roles_pass = array();
        foreach (array_unique($roles) as $name) {
            // 取得角色權限表
            $authorities = Arr::get($this->_roles, $name, array());
            // 允許的
            $allow_pass = $this->_is_match(Arr::get($authorities, 'allow', array()));
            // 禁止的
            $deny_pass = $this->_is_match(Arr::get($authorities, 'deny', array()));
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
     * @param array $denies 字串陣列
     * @return boolean
     */
    private function _is_match(array $list = array())
    {
        $m = $this->_request->method();
        $d = ($this->_request->directory() === "") ? TRUE : $this->_request->directory();
        $c = $this->_request->controller();
        $a = $this->_request->action();
        // 禁止的檢查器
        $checker = array();
        $match = FALSE;
        foreach ($list as $uri) {
            $authority = $this->_parse_uri($uri);
            // 檢查禁止的 method 部分
            $checker['method'] = (Arr::get($authority, 'method') === TRUE) ? TRUE : !strcasecmp($m, Arr::get($authority, 'method'));
            // 檢查禁止的 directory 部分
            $checker['directory'] = (Arr::get($authority, 'directory') === TRUE) ? TRUE : !strcasecmp($d, Arr::get($authority, 'directory'));
            // 檢查禁止的 controller 部分;
            $checker['controller'] = (Arr::get($authority, 'controller') === TRUE) ? TRUE : !strcasecmp($c, Arr::get($authority, 'controller'));
            // 檢查禁止的 action 部分
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
        // 取得 method 部分
        $method = strtoupper(Arr::get($parse_url, 'scheme', Guarder::WILDCARD));
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
                $directory = Arr::get($path_fragment, 0, '*');
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
                'method' => ($method === Guarder::WILDCARD) ? TRUE : $method,
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
