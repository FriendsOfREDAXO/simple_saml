<?php

namespace REDAXO\Simple_SAML\Modules;

class Modules
{
    public static $Modules = [];

    public static function setModule($Module)
    {
        self::$Modules[$Module->getKey()] = $Module;
    }

    public static function getCurrentModule()
    {
        return current(self::$Modules);
    }
}
