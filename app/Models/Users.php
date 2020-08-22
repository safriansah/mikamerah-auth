<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Users extends Model
{
    //
    public function token()
    {
        return $this->hasMany('App\Models\Token', 'id_user');
    }

    public function profile()
    {
        return $this->hasOne('App\Models\Profile', 'id_user');
    }
}
