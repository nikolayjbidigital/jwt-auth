<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth\Middleware;

use Tymon\JWTAuth\Exceptions\JWTException;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;

class GetUserFromToken extends BaseMiddleware
{
    /**
     * Handle an incoming request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Closure  $next
     * @return mixed
     */
    public function handle($request, \Closure $next)
    {
        $token = $this->auth->setRequest($request)->getToken();
        if (! $token = $this->auth->setRequest($request)->getToken()) {
           // return $this->respond('tymon.jwt.absent', 'token_not_provided', 400);
        }

        try {
            $user = $this->auth->authenticate($token);
        } catch (TokenExpiredException $e) {
            if($token){
                return $this->respond('tymon.jwt.expired', 'token_expired', $e->getStatusCode(), [$e]);
            }
        } catch (JWTException $e) {
            if($token){
                 return $this->respond('tymon.jwt.invalid', 'token_invalid', $e->getStatusCode(), [$e]);
            }
        }

        if($token){
         $this->events->fire('tymon.jwt.valid', $user);
        }
        return $next($request);
    }
}
