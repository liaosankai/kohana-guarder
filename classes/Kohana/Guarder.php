<?php

defined('SYSPATH') or die('No direct script access.');

class Kohana_Guarder {

    /**
     * Wildcard
     * 
     * @var string
     */
    const WILDCARD = '*';

    /**
     * Singleton Pattern
     * 
     * @access	public
     * @return	Deputy
     */
    public static function instance(array $config = array())
    {
        static $instance;

        if ($instance === NULL) {
            $instance = new Guarder($config);
        }

        return $instance;
    }

    /**
     * Parent resource
     * 
     * @access	public
     * @var		Deputy_Resource
     */
    protected $_resources;

    /**
     * Roles
     * 
     * @access	protected
     * @var		array
     */
    protected $_roles = array();

    /**
     * Configuration
     * 
     * @access	public
     * @var		array
     */
    protected $_config = array();

    /**
     * Initialize Account
     * 
     * @access	public
     * @return	void
     */
    public function __construct(array $config = array())
    {
        // Create root resource
        $this->_resources = new Deputy_Resource;

        // Handle configuration
        $this->_config = Arr::merge(Kohana::$config->load('guarder')->as_array(), $config);

        // Setup Guarder
        $this->_setup();
        
        Request::current();
    }

    /**
     * 
     */
    public function is_pass($role) {
        
    }
    
    /**
     * 
     * @param type $uri
     * @return type
     */
    private function _parse_uri($uri)
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
                'uri' => $uri,
                'map' => "{$method}://{$directory}/{$controller}/{$action}",
                'method' => ($method === Guarder::WILDCARD) ? TRUE : $method,
                'directory' => ($directory === Guarder::WILDCARD) ? TRUE : $directory,
                'controller' => ($controller === Guarder::WILDCARD) ? TRUE : $controller,
                'action' => ($action === Guarder::WILDCARD) ? TRUE : $action,
            );
        }
    }

    /**
     * Initialize Account
     * 
     * @access	public
     * @return	void
     */
    private function _setup()
    {
        $roles = Kohana::$config->load('guarder.roles')->as_array();
        foreach ($roles as $role => $power) {
            foreach ($power['allow'] as $key => $uri) {
                $roles[$role]['allow'][$key] = $this->_parse_uri($uri);
            }
            foreach ($power['deny'] as $key => $uri) {
                $roles[$role]['deny'][$key] = $this->_parse_uri($uri);
            }
        }
    }

}
