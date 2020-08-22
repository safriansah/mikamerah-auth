<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Token extends Model
{
    //
    protected $table = 'token';
    public function user()
    {
        return $this->belongsTo('App\Models\Users', 'id_user');
    }
}
