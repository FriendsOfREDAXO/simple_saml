<?php

namespace REDAXO\Simple_SAML\Modules;

class Modules
{
    private static $Modules = [];

    public static function setModule($Module)
    {
        self::$Modules[$Module->getKey()] = $Module;
    }

    /** @api */
    public static function getCurrentModule()
    {
        return current(self::$Modules);
    }
}
